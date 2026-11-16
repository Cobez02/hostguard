"""Rules over Defender's state, hardening settings, accounts, trusted roots and typed commands.

Findings in the "posture" category describe how well the PC is locked down. They never count
towards the compromise verdict. Settings that an intruder changes on purpose (Defender switched
off, WDigest turned on, a new administrator) are filed under "defender", "config" or "account"
and do count.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time

from .. import util
from ..model import Finding
from . import cmdline as cl

DAY = 86400.0
_NA = "n/a: must be an administrator"
_MS_ROOT = re.compile(r"microsoft|verisign|thawte|symantec enterprise mobile root for microsoft", re.I)
_SECURITY_HOSTS = re.compile(
    r"(?:^|\.)(?:microsoft\.com|windowsupdate\.com|windows\.com|live\.com|defender|virustotal\.com|malwarebytes\.com|"
    r"kaspersky\.|bitdefender\.|eset\.com|avast\.com|avg\.com|norton\.com|mcafee\.com|sophos\.com|trendmicro\.com|"
    r"symantec\.com|google\.com|paypal\.com|github\.com)", re.I)
_DOCKER_HOSTS = {"host.docker.internal", "gateway.docker.internal", "kubernetes.docker.internal"}

# Defender names threats "Type:Platform/Family". The type decides how worried to be.
_THREAT_CLASSES = [
    (("ransom",), "critical", "ransomware"),
    (("backdoor", "trojanspy", "pws", "trojandownloader", "trojandropper", "trojan", "worm", "virus", "rogue", "ddos",
      "spammer", "trojanclicker", "trojanproxy"), "high", "malware"),
    (("behavior", "exploit"), "high", "malicious behaviour"),
    (("virtool", "hacktool", "constructor", "monitoringtool", "remoteaccess", "tool"), "medium", "attack or dual-use tool"),
    (("pua", "puabundler", "puadlmanager", "adware", "browsermodifier", "softwarebundler", "program", "misleading",
      "joke", "app", "settingsmodifier"), "low", "unwanted software"),
]


def classify_threat(name: str) -> tuple[str, str]:
    """(severity, plain-language class) for a Defender threat name."""
    head = (name or "").split(":", 1)[0].lower().strip()
    for prefixes, sev, label in _THREAT_CLASSES:
        if head in prefixes:
            return sev, label
    return "high", "threat"


# Wrappers that AI coding agents put around the commands they run. Defender sometimes blocks such
# a command because a long scripted command line resembles a pasted attack. The hint is shown as
# evidence only: it never lowers a severity, because an attacker could add the same text.
_AGENT_WRAPPERS = ((".claude/shell-snapshots/", "the wrapper Claude Code's shell tool adds"),
                   ("$psdefaultparametervalues['out-file:encoding']", "the preamble Claude Code's PowerShell tool adds"))


def detection_finding(name: str, resource: str, when: float | None, handled: str | None, failed: bool,
                      collector: str, extra: dict | None = None) -> Finding:
    """One finding for one Defender detection, the same whether it was read from Defender's own
    history or from its event log (so the two sources collapse into one entry)."""
    sev, label = classify_threat(name)
    res = re.sub(r"\s+", " ", resource or "").strip()
    is_cmd = res.lower().startswith("cmdline:")
    subject = res.split(":_", 1)[-1] if ":_" in res[:12] else res
    if failed:
        sev, outcome = ("critical" if sev in ("high", "critical") else "high"), "Defender could NOT remove or block it"
    elif handled:
        outcome = f"Defender dealt with it ({handled.lower()})"
    else:
        outcome = "no clean-up event followed in the log"
    ev = {"threat": name, "detected": util.iso(when), "outcome": outcome}
    conf, tags = "high", []
    if is_cmd:
        program = util.split_command(subject)[0]
        ev.update({"launched_program": program, "command_starts": util.truncate(subject, 320), "command_length": len(subject)})
        title = f"Defender blocked a command it classifies as {label}: {name}"
        desc = ("Defender judged a program's command line, not a file, and stopped the program before it ran, so this "
                "command installed nothing. Commands pasted from fake CAPTCHA or 'fix it' pages are caught this way. "
                "So, now and then, are long scripted commands from developer tools and AI coding agents.")
        for marker, what in _AGENT_WRAPPERS:
            if marker in subject.lower():
                ev["launcher_hint"] = f"The command line carries {what}."
                conf, tags = "low", ["ai-agent-command"]
                break
        entity, actions = {}, []
    else:
        files = re.findall(r"file:_?([^;]+)", res) or ([subject] if re.match(r"^[a-z]:\\", subject, re.I) else [])
        ev["where"] = util.truncate(res, 700)
        title = f"Defender detected {label}: {name}"
        desc = ("A detection means something malicious or unwanted reached this PC, so the useful question is how it "
                "arrived. " + outcome + ".")
        entity = {"type": "file", "path": files[0].strip()} if files else {}
        actions = ["quarantine"] if files and failed else []
    ev.update({k: v for k, v in (extra or {}).items() if v not in (None, "", [])})
    return Finding(rule="defender.detection", title=title, severity=sev, confidence=conf, category="defender", kind="event",
                   when=when, collector=collector, description=desc, evidence=ev, entity=entity, actions=actions,
                   mitre=["T1204.004" if is_cmd else "T1204"], tags=tags, key_parts=(name.lower(), subject.lower()[:160]))


def _f(rule, title, sev, category, desc, evidence=None, conf="high", mitre=(), key=(), remediation="", actions=(),
       entity=None, collector="system", tags=()):
    return Finding(rule=rule, title=title, severity=sev, category=category, description=desc, confidence=conf,
                   evidence=evidence or {}, mitre=list(mitre), key_parts=tuple(key) or (rule,), remediation=remediation,
                   actions=list(actions), entity=entity or {}, collector=collector, tags=list(tags))


def _is_na(value) -> bool:
    return any(_NA in str(v).lower() for v in util.as_list(value))


def detect_defender(facts: dict) -> list[Finding]:
    out: list[Finding] = []
    d = facts.get("defender") or {}
    st, pr = d.get("status") or {}, d.get("prefs") or {}
    products = util.as_list(d.get("products"))
    others = [p for p in products if "defender" not in str(p.get("displayName", "")).lower()]
    other_on = [p for p in others if (int(p.get("productState") or 0) >> 12) & 0xF == 1]
    if not st:
        if other_on:
            out.append(_f("defender.third_party", f"Antivirus is provided by {other_on[0].get('displayName')}", "info",
                          "defender", "Microsoft Defender's status could not be read; another product is registered and on.",
                          {"products": [p.get("displayName") for p in products]}, conf="medium"))
        else:
            out.append(_f("defender.unavailable", "Microsoft Defender's status could not be read", "high", "defender",
                          "Windows did not answer the Defender status query and no other antivirus reports itself "
                          "as running. On a healthy PC this query always works.",
                          {"products": [p.get("displayName") for p in products]}, conf="medium", mitre=("T1562.001",),
                          remediation="Open Windows Security and check Virus & threat protection."))
        return out
    passive = str(st.get("AMRunningMode", "")).lower() not in ("normal", "")
    rtp_off = not st.get("RealTimeProtectionEnabled") or not st.get("AntivirusEnabled") or not st.get("AMServiceEnabled")
    if rtp_off:
        if other_on or passive:
            out.append(_f("defender.passive", "Microsoft Defender is in passive mode", "info", "defender",
                          f"Another antivirus ({', '.join(str(p.get('displayName')) for p in other_on) or 'unknown'}) "
                          "is registered as the active one.", {"mode": st.get("AMRunningMode")}, conf="medium"))
        else:
            out.append(_f("defender.realtime_off", "Real-time antivirus protection is OFF", "critical", "defender",
                          "Nothing is scanning files as they are opened or programs as they start. Malware turns "
                          "this off first; so do people who forget to turn it back on.",
                          {k: st.get(k) for k in ("RealTimeProtectionEnabled", "AntivirusEnabled", "AMServiceEnabled",
                                                  "IsTamperProtected")}, mitre=("T1562.001",),
                          remediation="Windows Security > Virus & threat protection > Manage settings > Real-time protection."))
    else:
        for key, what in (("BehaviorMonitorEnabled", "Behaviour monitoring"), ("IoavProtectionEnabled", "Scanning of downloads"),
                          ("OnAccessProtectionEnabled", "On-access scanning")):
            if st.get(key) is False:
                out.append(_f("defender.component_off", f"{what} is switched off in Defender", "high", "defender",
                              "Real-time protection is on but this part of it is not, which is not a state the "
                              "Windows Security app can produce by itself.", {key: False}, mitre=("T1562.001",), key=(key,)))
    if pr.get("DisableScriptScanning"):
        out.append(_f("defender.script_scanning_off", "Defender script scanning is disabled", "high", "defender",
                      "PowerShell, JavaScript and VBScript are not being inspected as they run.", mitre=("T1562.001",)))
    if st.get("IsTamperProtected") is False:
        out.append(_f("defender.tamper_off", "Tamper Protection is off", "medium", "defender",
                      "Any program with administrator rights can switch Defender off with one command. With Tamper "
                      "Protection on, only the Windows Security app can.", mitre=("T1562.001",),
                      remediation="Windows Security > Virus & threat protection > Manage settings > Tamper Protection."))
    age = st.get("AntivirusSignatureAge")
    if st.get("DefenderSignaturesOutOfDate") or (isinstance(age, int) and 7 <= age < 60000):
        out.append(_f("defender.signatures_old", f"Defender's definitions are {age} days old", "high" if (age or 0) >= 14 else "medium",
                      "defender", "Definitions normally update several times a day. Stale ones mean new malware is not "
                      "recognised, and can mean something is blocking updates.", {"age_days": age,
                                                                                    "version": st.get("AntivirusSignatureVersion")}))
    qs = st.get("QuickScanAge")
    if isinstance(qs, int) and qs >= 14:
        out.append(_f("posture.defender.no_recent_scan", "No Defender quick scan in the last two weeks" if qs < 60000 else
                      "Defender has never completed a quick scan", "low", "posture",
                      "Real-time protection covers files as they are used; scheduled scans catch what was already there.",
                      {"quick_scan_age_days": None if qs >= 60000 else qs}))

    # exclusions: malware adds itself here so Defender ignores it
    excl = []
    for key, label in (("ExclusionPath", "path"), ("ExclusionProcess", "process"), ("ExclusionExtension", "extension"),
                       ("ExclusionIpAddress", "ip")):
        vals = util.as_list(pr.get(key))
        if _is_na(vals):
            continue
        excl += [(label, str(v)) for v in vals if v]
    pol = (facts.get("registry") or {}).get("defender_policy") or {}
    for k, vals in (pol.get("policy_exclusions") or {}).items():
        excl += [("policy " + k.lower().rstrip("s"), v) for v in vals]
    for label, value in excl:
        low = value.lower().rstrip("\\")
        broad = low in ("c:", "c:\\users", "c:\\windows", "c:\\programdata", "c:\\windows\\temp") or low.endswith(("\\temp", "\\downloads", "\\public", "\\appdata", "\\appdata\\local", "\\appdata\\roaming")) \
            or (label.endswith("extension") and low.lstrip(".") in ("exe", "dll", "ps1", "bat", "cmd", "js", "vbs", "scr", "tmp")) \
            or (label.endswith("process") and util.basename(low) in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "svchost.exe"))
        out.append(_f("defender.exclusion", f"Defender is told to ignore {label}: {value}", "high" if broad else "medium",
                      "defender", "Nothing under an exclusion is scanned. Developer tools add narrow ones; malware "
                      "adds broad ones for the folder it lives in." + (" This one is broad enough to hide almost anything." if broad else ""),
                      {"type": label, "value": value}, conf="medium" if broad else "low", mitre=("T1562.001",),
                      key=(label, low), remediation="Windows Security > Virus & threat protection > Manage settings > Exclusions."))
    for k in ("DisableAntiSpyware", "DisableAntiVirus", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
              "DisableOnAccessProtection", "DisableScanOnRealtimeEnable", "DisableIOAVProtection"):
        if pol.get(k) == 1:
            out.append(_f("defender.policy_disable", f"A policy registry value tries to disable Defender ({k})", "high", "defender",
                          "Home PCs have no policy here. Malware writes these values to switch Defender off; Tamper "
                          "Protection ignores them, but the attempt is the finding.",
                          {"value": rf"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender ... {k} = 1"}, mitre=("T1562.001",), key=(k,)))

    # detection history as Defender reports it (needs administrator rights on some builds)
    names = {str(t.get("ThreatID")): t for t in util.as_list(d.get("threats"))}
    for det in util.as_list(d.get("detections")):
        t = names.get(str(det.get("ThreatID")), {})
        name = t.get("ThreatName") or f"threat {det.get('ThreatID')}"
        when = util.parse_time(det.get("Detected"))
        active = bool(t.get("IsActive")) or det.get("ActionSuccess") is False
        res = [str(r) for r in util.as_list(det.get("Resources"))]
        out.append(detection_finding(name, res[0] if res else "", when, None if active else "action taken", active, "system",
                                     {"process": det.get("ProcessName"), "executed": t.get("DidThreatExecute")}))
    return out


def detect_posture(facts: dict) -> list[Finding]:
    out: list[Finding] = []
    r = facts.get("registry") or {}
    sysf = facts.get("system") or {}
    pr = (facts.get("defender") or {}).get("prefs") or {}
    st = (facts.get("defender") or {}).get("status") or {}
    uac = r.get("uac") or {}
    if uac.get("EnableLUA") == 0:
        out.append(_f("posture.uac.disabled", "User Account Control is turned off", "high", "posture",
                      "Every program you run has full administrator rights with no prompt.", {"EnableLUA": 0},
                      mitre=("T1548.002",)))
    elif uac.get("ConsentPromptBehaviorAdmin") == 0:
        out.append(_f("posture.uac.never_notify", "UAC is set to never notify", "medium", "posture",
                      "Programs can elevate to administrator silently.", {"ConsentPromptBehaviorAdmin": 0}, mitre=("T1548.002",)))
    if uac.get("LocalAccountTokenFilterPolicy") == 1:
        out.append(_f("config.remote_uac_off", "Remote UAC filtering is disabled", "medium", "config",
                      "Local administrator accounts get full rights over the network. Lateral-movement tools need "
                      "this and some set it themselves.", {"LocalAccountTokenFilterPolicy": 1}, conf="medium", mitre=("T1112", "T1021.002")))
    for prof in util.as_list(sysf.get("firewall")):
        if prof.get("enabled") is False:
            out.append(_f("posture.firewall.off", f"Windows Firewall is off for the {prof.get('name')} profile", "high", "posture",
                          "Every listening service on this PC is reachable from that kind of network.", prof,
                          mitre=("T1562.004",), key=(prof.get("name"),)))
    for prof, val in (r.get("firewall_policy") or {}).items():
        if val == 0:
            out.append(_f("config.firewall_policy_off", f"A policy value switches the firewall off ({prof})", "high", "config",
                          "Home PCs have no firewall policy. Something wrote this value.", {prof: 0}, mitre=("T1562.004",), key=(prof,)))
    rdp = r.get("rdp") or {}
    if rdp.get("deny") == 0:
        nla = rdp.get("nla") == 1
        out.append(_f("posture.rdp.enabled", "Remote Desktop is enabled", "medium", "posture",
                      "This PC accepts remote logons on port " + str(rdp.get("port") or 3389) + ". That is a setting you "
                      "may have chosen. It is also the most attacked service on the internet, so it should never be "
                      "reachable from outside your network without a VPN." + ("" if nla else " Network Level Authentication is off, which makes it worse."),
                      {"port": rdp.get("port"), "network_level_authentication": nla}, conf="medium", mitre=("T1021.001",),
                      remediation="Settings > System > Remote Desktop. Turn it off if you do not use it."))
    if r.get("wdigest") == 1:
        out.append(_f("config.wdigest_cleartext", "Windows is set to keep logon passwords in memory in clear text", "high",
                      "config", "WDigest's UseLogonCredential is 1. Modern Windows leaves it off; attackers switch it on "
                      "so the next logon can be harvested.", {"UseLogonCredential": 1}, mitre=("T1112", "T1003.001")))
    lsa = r.get("lsa") or {}
    if not lsa.get("RunAsPPL") and not lsa.get("RunAsPPLBoot"):
        out.append(_f("posture.lsa_protection_off", "LSA protection is off", "low", "posture",
                      "The process that holds your credentials is not protected from being read by other "
                      "administrator-level programs.", {"RunAsPPL": lsa.get("RunAsPPL")}, mitre=("T1003.001",),
                      remediation="Windows Security > Device security > Core isolation > Local Security Authority protection."))
    if lsa.get("DisableRestrictedAdmin") == 0:
        out.append(_f("config.restricted_admin", "Restricted Admin mode for Remote Desktop was enabled", "medium", "config",
                      "It allows pass-the-hash logons over RDP and is off by default.", {"DisableRestrictedAdmin": 0},
                      conf="medium", mitre=("T1112", "T1550.002")))
    if r.get("smb1_server") == 1 or r.get("smb1_client_start") in (0, 1, 2, 3):
        out.append(_f("posture.smb1", "The obsolete SMBv1 protocol is enabled", "medium", "posture",
                      "SMBv1 is what WannaCry and NotPetya spread through.", {"server": r.get("smb1_server"),
                                                                              "client_driver_start": r.get("smb1_client_start")}))
    aie = r.get("always_install_elevated") or [None, None]
    if aie[0] == 1 and aie[1] == 1:
        out.append(_f("posture.always_install_elevated", "Any user can install software as SYSTEM (AlwaysInstallElevated)", "high",
                      "posture", "Both policy values are set, so any MSI package runs with full system rights.", mitre=("T1548.002",)))
    if r.get("test_signing"):
        out.append(_f("config.test_signing", "Windows is booted in test-signing mode", "high", "config",
                      "Driver signature enforcement is relaxed, so unsigned kernel drivers can load. Driver developers "
                      "set this; so do rootkit installers.", conf="medium", mitre=("T1553.006",)))
    if r.get("kernel_debug"):
        out.append(_f("config.kernel_debug", "Windows is booted with kernel debugging enabled", "medium", "config",
                      "A kernel debugger can read and change anything on the PC.", conf="medium", mitre=("T1553.006",)))
    if r.get("driver_blocklist") == 0:
        out.append(_f("posture.driver_blocklist_off", "The vulnerable-driver blocklist is off", "medium", "posture",
                      "Windows will load drivers that are known to be exploitable.", mitre=("T1068",)))
    if r.get("hvci") != 1:
        out.append(_f("posture.memory_integrity_off", "Memory integrity (core isolation) is off", "low", "posture",
                      "Kernel code integrity is not enforced by the hypervisor.",
                      remediation="Windows Security > Device security > Core isolation."))
    auto = r.get("autologon") or {}
    if str(auto.get("enabled")) == "1" and auto.get("password_stored"):
        out.append(_f("posture.autologon_password", "Automatic logon stores your password in the registry", "medium", "posture",
                      "Any program running on this PC can read it.", mitre=("T1552.002",)))
    if r.get("wu_no_auto_update") == 1:
        out.append(_f("config.updates_disabled", "Automatic Windows updates are disabled by policy", "medium", "config",
                      "Home PCs have no update policy unless someone set one.", conf="low", mitre=("T1562",)))
    if str(r.get("smartscreen") or "").lower() == "off" or r.get("smartscreen_policy") == 0:
        out.append(_f("posture.smartscreen_off", "SmartScreen is turned off", "medium", "posture",
                      "Downloaded programs are no longer checked against Microsoft's reputation service."))
    hot = sysf.get("hotfix") or {}
    age = util.age_days(util.parse_time(hot.get("installed")))
    if age is not None and age > 45:
        out.append(_f("posture.updates_old", f"No Windows update installed for {int(age)} days", "medium", "posture",
                      "Security fixes ship monthly.", {"last_update": hot.get("id"), "installed": hot.get("installed")}))
    if sysf.get("secureboot") is False:
        out.append(_f("posture.secure_boot_off", "Secure Boot is off", "medium", "posture",
                      "Boot-level malware is not blocked at startup.", mitre=("T1542.003",)))
    drive = (os.environ.get("SystemDrive") or "C:").upper()
    for vol in util.as_list(sysf.get("bitlocker")):
        if str(vol.get("mount", "")).upper().startswith(drive) and str(vol.get("protection", "")).lower() == "off":
            out.append(_f("posture.bitlocker_off", "The system drive is not encrypted", "low", "posture",
                          "Anyone with the PC or its disk in hand can read every file on it. This is about theft, not malware.",
                          {"drive": vol.get("mount"), "status": vol.get("status")},
                          remediation="Settings > Privacy & security > Device encryption (or BitLocker)."))
    custom = [s for s in util.as_list(sysf.get("shares")) if not str(s.get("name", "")).endswith("$")]
    if custom:
        out.append(_f("posture.shares", f"{len(custom)} folder(s) shared on the network", "low", "posture",
                      "Shared folders are reachable by other devices on the network.",
                      {"shares": [f"{s.get('name')} -> {s.get('path')}" for s in custom][:10]}, conf="low"))
    if pr:
        pua = pr.get("PUAProtection")
        if pua in (0, 2):
            out.append(_f("posture.defender.pua", "Defender detects unwanted apps but does not block them" if pua == 2
                          else "Blocking of potentially unwanted apps is off", "low", "posture",
                          "Adware, bundlers and coin miners that fall short of 'malware' are let through.",
                          {"PUAProtection": {0: "off", 2: "audit only"}[pua]},
                          remediation="Windows Security > App & browser control > Reputation-based protection."))
        if pr.get("MAPSReporting") == 0:
            out.append(_f("posture.defender.cloud_off", "Defender's cloud-delivered protection is off", "medium", "posture",
                          "Independent tests show Defender's detection falls from about 99.9% to about 82% without it."))
        if not util.as_list(pr.get("AsrIds")):
            out.append(_f("posture.defender.no_asr", "No Attack Surface Reduction rules are configured", "low", "posture",
                          "These free Defender rules block the commonest infection steps (Office starting scripts, "
                          "credential theft from LSASS, obfuscated scripts). They are off until someone turns them on."))
        if pr.get("EnableControlledFolderAccess") in (0, None):
            out.append(_f("posture.defender.cfa_off", "Controlled folder access (ransomware protection) is off", "info", "posture",
                          "When on, only trusted programs can change files in Documents, Pictures and Desktop."))
        if pr.get("EnableNetworkProtection") in (0, None):
            out.append(_f("posture.defender.network_protection_off", "Defender network protection is off", "info", "posture",
                          "When on, connections to known malicious sites are blocked for every program, not only the browser."))
    if str(st.get("SmartAppControlState", "")).lower() == "off":
        out.append(_f("posture.smart_app_control_off", "Smart App Control is off", "info", "posture",
                      "It blocks unsigned and unknown programs outright. Developer machines usually cannot use it."))
    if r.get("ps_scriptblock_logging") != 1 or r.get("proc_cmdline_audit") != 1:
        out.append(_f("posture.logging_gaps", "Windows is not recording command lines or PowerShell scripts", "info", "posture",
                      "Without these two logs, a command that ran and exited leaves almost no trace to investigate.",
                      {"powershell_script_block_logging": r.get("ps_scriptblock_logging") == 1,
                       "process_command_line_auditing": r.get("proc_cmdline_audit") == 1}))
    return out


def detect_accounts(facts: dict) -> list[Finding]:
    out: list[Finding] = []
    acc = facts.get("accounts") or {}
    current = str(acc.get("current") or "").split("\\")[-1].lower()
    users = util.as_list(acc.get("users"))
    groups = acc.get("groups") or {}
    now = time.time()
    for u in users:
        name = str(u.get("name") or "")
        low = name.lower()
        ent = {"type": "account", "name": name}
        if not u.get("enabled"):
            continue
        sid = str(u.get("sid") or "")
        if sid.endswith("-500"):
            out.append(_f("account.builtin_admin_enabled", "The built-in Administrator account is enabled", "medium", "account",
                          "It is disabled on a normal Windows 11 PC and has no lockout. Attackers enable it for a way back in.",
                          {"last_logon": u.get("lastlogon")}, conf="medium", mitre=("T1078.003",), entity=ent, actions=("disable_user",)))
        elif sid.endswith("-501"):
            out.append(_f("account.guest_enabled", "The Guest account is enabled", "medium", "account",
                          "Anyone can log on without a password.", mitre=("T1078.001",), entity=ent, actions=("disable_user",)))
        elif name.endswith("$"):
            out.append(_f("account.hidden", f"Local user account with a hidden-style name: {name}", "high", "account",
                          "A trailing $ hides an account from some listings. Windows does not create local users like this.",
                          {"created_or_password_set": u.get("pwset")}, mitre=("T1136.001", "T1564.002"), key=(low,), entity=ent,
                          actions=("disable_user",)))
        elif low != current and low not in ("defaultaccount", "wdagutilityaccount"):
            pw = util.parse_time(u.get("pwset"))
            recent = pw is not None and now - pw < 30 * DAY
            out.append(_f("account.other_user", f"Another enabled local account: {name}", "medium" if recent else "low", "account",
                          ("Its password was set in the last 30 days. " if recent else "") + "Make sure you recognise it.",
                          {"password_set": u.get("pwset"), "last_logon": u.get("lastlogon") or "never",
                           "description": u.get("description")}, conf="low", mitre=("T1136.001",), key=(low,), entity=ent,
                          actions=("disable_user",)))
    admins = (groups.get("S-1-5-32-544") or {}).get("members") or []
    for m in admins:
        short = str(m.get("name") or "").split("\\")[-1].lower()
        sid = str(m.get("sid") or "")
        if short == current or sid.endswith("-500") or not short:
            continue
        out.append(_f("account.extra_admin", f"Additional administrator: {m.get('name')}", "medium", "account",
                      "Every administrator can change anything on this PC.", {"sid": sid, "source": m.get("source")},
                      conf="low", mitre=("T1098", "T1078.003"), key=(short,), entity={"type": "account", "name": short}))
    for sid, label, tech in (("S-1-5-32-555", "Remote Desktop Users", "T1021.001"), ("S-1-5-32-580", "Remote Management Users", "T1021.006")):
        members = (groups.get(sid) or {}).get("members") or []
        if members:
            out.append(_f("account.remote_group", f"{len(members)} account(s) in {label}", "medium", "account",
                          "Members may log on to this PC remotely without being administrators. The group is empty by default.",
                          {"members": [m.get("name") for m in members]}, conf="low", mitre=(tech, "T1098"), key=(sid,)))
    return out


def detect_config(facts: dict) -> list[Finding]:
    """Hosts file, proxies, trusted roots, browser policies and typed commands."""
    out: list[Finding] = []
    for e in (facts.get("hosts") or {}).get("entries") or []:
        names = [n.lower() for n in e["names"]]
        if set(names) <= _DOCKER_HOSTS or names in (["localhost"], ["localhost", "localhost.localdomain"]):
            continue
        targets = [n for n in names if _SECURITY_HOSTS.search(n)]
        if targets:
            out.append(_f("config.hosts.redirect", f"The hosts file redirects {targets[0]}", "high", "config",
                          "A hosts entry overrides DNS. Redirecting an update, security or login site is how malware "
                          "blocks updates or phishes credentials.", {"ip": e["ip"], "names": e["names"]},
                          mitre=("T1565.001",), key=(e["ip"], *names)))
        else:
            out.append(_f("config.hosts.entry", f"Custom hosts file entry: {names[0]}", "info", "config",
                          "Developers add these. Listed so you can confirm it is yours.", {"ip": e["ip"], "names": e["names"]},
                          conf="low", key=(e["ip"], *names)))
    for scope, p in (facts.get("proxy") or {}).items():
        if scope == "env":
            for k, v in p.items():
                out.append(_f("config.proxy.env", f"{k} environment variable routes traffic through {v}", "low", "config",
                              "Command-line tools send their traffic there.", {k: v}, conf="low", key=(k, v)))
            continue
        if p.get("pac"):
            local = re.match(r"^(?:https?://(?:127\.0\.0\.1|localhost|\[::1\])|file:)", p["pac"], re.I)
            out.append(_f("config.proxy.pac", "A proxy auto-configuration script is set", "medium" if local else "high", "config",
                          "The script decides, per site, where your browser traffic goes. Banking trojans install one "
                          "to intercept selected sites.", {"scope": scope, "script": p["pac"]}, conf="medium",
                          mitre=("T1557", "T1090"), key=(scope, p["pac"])))
        if p.get("enabled") and p.get("server"):
            host = p["server"].split("=")[-1].split(":")[0]
            local = host in ("127.0.0.1", "localhost", "::1")
            out.append(_f("config.proxy.server", f"System proxy is set to {p['server']}", "low" if local else "medium", "config",
                          "All browser traffic passes through it." + (" It is a program on this PC, which is what "
                          "a local testing proxy looks like, and also what traffic-stealing malware looks like." if local else ""),
                          {"scope": scope, "server": p["server"]}, conf="low", mitre=("T1090",), key=(scope, p["server"])))
    for c in facts.get("certs") or []:
        stores = c.get("stores") or []
        subject = c.get("subject", "")
        installed = util.iso(c.get("installed"))
        ev = {"subject": subject, "issuer": c.get("issuer"), "thumbprint": c.get("thumbprint"), "installed": installed,
              "valid_until": c.get("not_after"), "stores": stores}
        if "user" in stores or "user_policy" in stores:
            out.append(_f("config.root_cert.user", f"Root certificate trusted for your account only: {_cn(subject)}", "medium",
                          "config", "It was added without administrator rights. Whoever holds its private key can "
                          "impersonate any website to you. Interception proxies install one on purpose; so does malware.",
                          ev, conf="low", mitre=("T1553.004",), key=(c.get("thumbprint"),)))
        elif ("machine" in stores or "policy" in stores or "enterprise" in stores) and "authroot" not in stores \
                and not _MS_ROOT.search(subject):
            out.append(_f("config.root_cert.machine", f"Root certificate installed on this PC by hand: {_cn(subject)}", "medium",
                          "config", "It is not one of the roots Windows ships or Microsoft distributes. Development tools, "
                          "VPNs and antivirus products add these; so does anything that wants to read HTTPS traffic.",
                          ev, conf="low", mitre=("T1553.004",), key=(c.get("thumbprint"),)))
    for p in facts.get("browser_policies") or []:
        sev = "high" if p["policy"] in ("ExtensionInstallForcelist", "Extensions\\Install", "ProxyServer", "ProxyPacUrl") else "medium"
        out.append(_f("config.browser_policy", f"{p['browser']} is managed by a policy: {p['policy']}", sev, "browser",
                      "Home PCs have no browser policies. Adware and stealers set them to force an extension in or "
                      "reroute traffic, which is why the browser then says it is 'managed by your organization'.",
                      p, conf="medium", mitre=("T1176",), key=(p["browser"], p["scope"], p["policy"], p["value"])))
    typed = facts.get("typed") or {}
    for source, label, items in (("run_box", "the Run box", typed.get("run_box") or []),
                                 ("address_bar", "the Explorer address bar", typed.get("address_bar") or []),
                                 ("ps_history", "PowerShell", typed.get("ps_history") or [])):
        for line in items:
            hits = cl.analyse_command(line)
            if not hits and source != "ps_history":
                low = line.lower()
                if re.search(r"\b(?:powershell|pwsh|mshta|cmd(?:\.exe)?\s+/c|curl|wscript|cscript|msiexec)\b", low) and "http" in low:
                    out.append(_f("config.typed.remote_command", f"A command that fetches from the internet was pasted into {label}",
                                  "high", "config", "Nobody types these by hand. Fake CAPTCHA and 'fix your browser' pages "
                                  "tell visitors to paste one (ClickFix).", {"command": util.truncate(line, 600), "urls": cl.urls_in(line)},
                                  conf="medium", mitre=("T1204.004", "T1059"), key=(source, line[:200])))
            for h in hits:
                sev = h.rule.severity
                conf = h.rule.confidence
                title = f"{h.rule.title} (typed into {label})"
                vendor = cl.known_installer(line) if h.rule.id == "cmd.download_cradle" else None
                if vendor:
                    sev, conf, title = "low", "low", f"{title}: the published installer for {vendor}"
                elif source != "ps_history":
                    sev, conf = ("critical" if sev in ("high", "critical") else "high"), "high"
                out.append(_f("config.typed." + h.rule.id, title, sev, "config",
                              (h.rule.why + " " if h.rule.why else "") + ("This was entered through the Run box or address "
                              "bar, which is exactly what ClickFix lures ask for." if source != "ps_history" else
                              "It is in your PowerShell command history, so it was run interactively as you."),
                              {"command": util.truncate(line, 600), "matched": h.match, "urls": cl.urls_in(line)}, conf=conf,
                              mitre=h.rule.mitre, key=(source, h.rule.id, line[:200]), tags=("clickfix-style",) if source != "ps_history" else ()))
    remote = [s for s in facts.get("software") or [] if s.get("remote_access")]
    if remote:
        out.append(_f("posture.remote_software", f"Remote access software installed: {', '.join(s['name'] for s in remote[:6])}",
                      "low", "posture", "Each is a way into this PC for whoever holds the account or key behind it.",
                      {"programs": [f"{s['name']} {s['version']}".strip() for s in remote]}, conf="low", mitre=("T1219",),
                      key=tuple(sorted(s["name"].lower() for s in remote))))
    return out


def _cn(subject: str) -> str:
    m = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject or "")
    return (m.group(1) or m.group(2)).strip() if m else util.truncate(subject, 60)


def detect(facts: dict) -> list[Finding]:
    return detect_defender(facts) + detect_posture(facts) + detect_accounts(facts) + detect_config(facts)


def inventory(facts: dict) -> dict[str, dict[str, dict]]:
    """Accounts, root certificates and administrators, for the baseline."""
    acc = facts.get("accounts") or {}
    inv: dict[str, dict[str, dict]] = {"account": {}, "admin": {}, "root_cert": {}}
    for u in util.as_list(acc.get("users")):
        inv["account"][str(u.get("name", "")).lower()] = {"name": u.get("name"), "enabled": u.get("enabled")}
    for m in ((acc.get("groups") or {}).get("S-1-5-32-544") or {}).get("members") or []:
        inv["admin"][str(m.get("sid") or m.get("name"))] = {"name": m.get("name")}
    for c in facts.get("certs") or []:
        if "authroot" not in (c.get("stores") or []):
            inv["root_cert"][c.get("thumbprint", "")] = {"subject": c.get("subject"), "stores": c.get("stores")}
    return inv


def is_private_dns(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False
