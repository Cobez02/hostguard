"""Rules over Windows event logs: what happened on this PC while nobody was watching.

Each finding is an event (it happened at a point in time and stays on record until you resolve
it). Repeats of the same thing collapse into one finding with a count.
"""

from __future__ import annotations

import html
import re
import time
from collections import defaultdict

from .. import util
from ..collect import eventlogs as logs
from ..model import Finding, SEV_ORDER
from . import cmdline as cl
from .system import detection_finding

_SECURITY_SERVICES = {"windefend", "wdnissvc", "sense", "wscsvc", "mpssvc", "securityhealthservice", "eventlog",
                      "mdcoresvc", "sysmon", "sysmon64", "wuauserv"}
_REMOTE_EXEC_SERVICES = re.compile(r"^(?:psexesvc|paexec|remcom|csexec|winexesvc|smbexec|btobto|meterpreter)", re.I)
_SHELL_IMAGE = re.compile(r"^\s*\"?(?:%comspec%|(?:[a-z]:\\windows\\system32\\)?(?:cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(?:\.exe)?)\"?(?:\s|$)", re.I)
_HOST_APP = re.compile(r"HostApplication=(.*?)(?:\r?\n\s*EngineVersion=|\Z)", re.S)
_DEFENDER_DISABLE = re.compile(
    r"\\(?:real-time protection\\disable\w+|disableantispyware|disableantivirus|features\\tamperprotection|"
    r"spynet\\(?:spynetreporting|submitsamplesconsent)|disablescriptscanning|disableioavprotection)\s*=\s*(0x[0-9a-f]+)", re.I)
_EXCLUSION = re.compile(r"\\windows defender\\exclusions\\(paths|processes|extensions|ipaddresses)\\(.+?)\s*=\s*0x", re.I)
_PRIVATE_SIDS = ("S-1-5-18", "S-1-5-19", "S-1-5-20")
_ADMIN_PORTS = {"3389", "445", "5985", "5986", "22", "135", "139", "5900", "23"}


class _Bucket:
    """Collapses repeats: one finding per key, remembering the newest event and the count."""

    def __init__(self) -> None:
        self.items: dict[tuple, dict] = {}

    def add(self, key: tuple, when: float | None, **fields) -> None:
        cur = self.items.get(key)
        if cur is None:
            self.items[key] = {"count": 1, "first": when, "last": when, **fields}
            return
        cur["count"] += 1
        if when and (not cur["last"] or when > cur["last"]):
            cur["last"] = when
            for k, v in fields.items():
                if k == "evidence":
                    cur[k] = v
        if when and (not cur["first"] or when < cur["first"]):
            cur["first"] = when

    def findings(self) -> list[Finding]:
        out = []
        for key, it in self.items.items():
            ev = dict(it.get("evidence") or {})
            ev["last_seen_in_log"] = util.iso(it["last"])
            if it["count"] > 1:
                ev["times"] = it["count"]
                ev["first_seen_in_log"] = util.iso(it["first"])
            out.append(Finding(rule=it["rule"], title=it["title"], severity=it["severity"], confidence=it.get("confidence", "medium"),
                               category=it.get("category", "eventlog"), description=it.get("description", ""), evidence=ev,
                               entity=it.get("entity") or {}, mitre=list(it.get("mitre") or ()), actions=list(it.get("actions") or ()),
                               remediation=it.get("remediation", ""), kind="event", when=it["last"], collector="eventlogs",
                               key_parts=key, tags=list(it.get("tags") or ())))
        return out


def _text_hits(b: _Bucket, text: str, scope: str, prefix: str, title_fmt: str, when, evidence: dict, key_tail: tuple,
               extra_mitre=(), why=""):
    hits = cl.analyse_command(text) if scope == "cmdline" else cl.match_text(text, "script")
    for h in hits:
        ev = dict(evidence)
        ev["matched"] = h.match
        urls = cl.urls_in(text)
        if urls:
            ev["urls"] = urls
        sev, conf, title, tags = h.rule.severity, h.rule.confidence, title_fmt.format(what=h.rule.title), []
        vendor = cl.known_installer(text) if h.rule.id == "cmd.download_cradle" else None
        if vendor:
            sev, conf, title, tags = "low", "low", f"{title} (the published installer for {vendor})", ["known-installer"]
        b.add((prefix + h.rule.id, *key_tail), when, rule=prefix + h.rule.id, title=title, severity=sev, confidence=conf,
              description=(h.rule.why + " " if h.rule.why else "") + why,
              mitre=list(h.rule.mitre) + list(extra_mitre), evidence=ev, tags=tags)
    return hits


def _system(b: _Bucket, events: list[dict]) -> None:
    new_services = []
    for e in events:
        d = e["data"]
        if e["id"] == 7045:
            name, image = d.get("ServiceName", ""), d.get("ImagePath", "")
            low = image.lower()
            if "\\windows defender\\" in low or "\\microsoft\\windows defender" in low:
                continue
            ev = {"service": name, "image_path": util.truncate(image, 600), "account": d.get("AccountName"),
                  "start": d.get("StartType"), "type": d.get("ServiceType"), "installed": util.iso(e["time"])}
            ent = {"type": "autorun", "kind": "service", "name": name, "location": "HKLM\\System\\CurrentControlSet\\Services\\" + name,
                   "command": image, "path": util.split_command(image)[0]}
            hit = _text_hits(b, image, "cmdline", "evt.service.", "A service was installed that runs: {what}", e["time"], ev,
                             (name.lower(), low[:200]), ("T1543.003",), "It was registered as a Windows service, so it runs as SYSTEM.")
            if _SHELL_IMAGE.match(image):
                pipe = "\\\\.\\pipe\\" in low
                b.add(("evt.service.shell", name.lower(), low[:200]), e["time"], rule="evt.service.shell",
                      title=f"A service was installed whose program is a shell: {name}", severity="critical" if pipe else "high",
                      confidence="high", mitre=["T1569.002", "T1543.003"], evidence=ev, entity=ent, actions=["disable_autorun"],
                      description="Remote-execution tools and privilege-escalation tricks create short-lived services "
                                  "like this to run a command as SYSTEM." + (" Writing to a named pipe is the classic get-SYSTEM move." if pipe else ""))
            elif _REMOTE_EXEC_SERVICES.match(name):
                b.add(("evt.service.remote_exec", name.lower()), e["time"], rule="evt.service.remote_exec",
                      title=f"A remote-execution service was installed: {name}", severity="high", confidence="medium",
                      mitre=["T1569.002", "T1021.002"], evidence=ev, entity=ent,
                      description="This is the service PsExec-style tools leave behind when someone runs commands on this PC from another machine.")
            elif not hit:
                zone = util.path_zone(util.split_command(image)[0])
                if zone in util.HIGH_RISK or (zone == "appdata" and d.get("AccountName", "").lower() == "localsystem"):
                    b.add(("evt.service.temp_path", name.lower(), low[:200]), e["time"], rule="evt.service.temp_path",
                          title=f"A SYSTEM service was installed from a user-writable folder: {name}", severity="medium",
                          confidence="low", mitre=["T1543.003"], evidence=ev, entity=ent, actions=["disable_autorun"],
                          description="Installers and hardware tools sometimes do this for a moment. Malware that has "
                                      "gained administrator rights does it to stay.")
            new_services.append(f"{util.iso(e['time'])[:16]}  {name}  {util.truncate(image, 110)}")
        elif e["id"] == 7040:
            svc = (d.get("param4") or "").lower()
            if svc in _SECURITY_SERVICES and "disabled" in (d.get("param3") or "").lower():
                b.add(("evt.service.security_disabled", svc), e["time"], rule="evt.service.security_disabled",
                      title=f"A security service was set to disabled: {d.get('param1')}", severity="high", confidence="medium",
                      mitre=["T1562.001"], evidence={"service": svc, "from": d.get("param2"), "to": d.get("param3")},
                      description="The service will not start again until someone re-enables it.")
        elif e["id"] == 104:
            b.add(("evt.log_cleared", d.get("Channel", "").lower(), int(e["time"] or 0)), e["time"], rule="evt.log_cleared",
                  title=f"The {d.get('Channel') or 'event'} log was cleared", severity="high", confidence="medium", mitre=["T1070.001"],
                  evidence={"log": d.get("Channel"), "by": d.get("SubjectUserName"), "when": util.iso(e["time"])},
                  description="Clearing a log removes the record of what happened before. People rarely do it by hand.")
    if new_services:
        b.add(("evt.service.inventory",), max((e["time"] or 0) for e in events if e["id"] == 7045), rule="evt.service.inventory",
              title=f"{len(new_services)} service installation(s) recorded in the System log", severity="info", confidence="low",
              category="eventlog", evidence={"services": new_services[:40]},
              description="Listed for context. Driver updates, games with anti-cheat and app updates all install services.")


def _defender(b: _Bucket, events: list[dict]) -> None:
    handled: dict[str, str] = {}
    failed: set[str] = set()
    for e in events:
        d = e["data"]
        det = d.get("Detection ID") or ""
        if e["id"] in (1117, 1007):
            handled[det] = d.get("Action Name") or "action taken"
        elif e["id"] in (1118, 1119, 1008):
            failed.add(det)
    for e in sorted(events, key=lambda x: x["time"] or 0):
        d = e["data"]
        if e["id"] in (1116, 1006, 1015):
            name = d.get("Threat Name") or d.get("Name") or "unknown threat"
            det = d.get("Detection ID") or ""
            proc = d.get("Process Name") or ""
            f = detection_finding(name, d.get("Path") or "", e["time"], handled.get(det), det in failed, "eventlogs",
                                  {"defender_severity": d.get("Severity Name"), "process": "" if proc == "Unknown" else proc})
            b.add(f.key_parts, e["time"], rule=f.rule, title=f.title, severity=f.severity, confidence=f.confidence,
                  category=f.category, mitre=f.mitre, entity=f.entity, actions=f.actions, evidence=f.evidence,
                  description=f.description, tags=f.tags)
        elif e["id"] == 5001:
            b.add(("evt.defender.rtp_disabled", int((e["time"] or 0) // 3600)), e["time"], rule="evt.defender.rtp_disabled",
                  title="Defender real-time protection was switched off", severity="high", confidence="medium", category="defender",
                  mitre=["T1562.001"], evidence={"when": util.iso(e["time"])},
                  description="Real-time protection was disabled at this time. Check whether it was you. The current state "
                              "is reported separately.")
        elif e["id"] in (5010, 5012):
            b.add(("evt.defender.scanning_disabled", e["id"], int((e["time"] or 0) // 3600)), e["time"], rule="evt.defender.scanning_disabled",
                  title="Defender scanning was disabled", severity="high", confidence="medium", category="defender", mitre=["T1562.001"],
                  evidence={"when": util.iso(e["time"]), "event": e["id"]}, description="Antimalware scanning was turned off.")
        elif e["id"] == 5013:
            b.add(("evt.defender.tamper_blocked", (d.get("Changed Type") or d.get("Value") or "")[:200]), e["time"],
                  rule="evt.defender.tamper_blocked", title="Something tried to change Defender's settings and was blocked",
                  severity="medium", confidence="medium", category="defender", mitre=["T1562.001"],
                  evidence={k: util.truncate(v, 300) for k, v in d.items() if k not in ("Product Name", "Product Version")},
                  description="Tamper Protection refused a change to Defender. Legitimate software does not normally try.")
        elif e["id"] in (5007, 5004):
            new, old = d.get("New Value") or "", d.get("Old Value") or ""
            m = _EXCLUSION.search(new)
            if m:
                kind, value = m.group(1).lower().rstrip("s"), m.group(2)
                removed = any(_EXCLUSION.search(x["data"].get("Old Value") or "") and value.lower() in (x["data"].get("Old Value") or "").lower()
                              and not (x["data"].get("New Value") or "").strip() and (x["time"] or 0) > (e["time"] or 0) for x in events)
                b.add(("evt.defender.exclusion_added", kind, value.lower()), e["time"], rule="evt.defender.exclusion_added",
                      title=f"A Defender exclusion was added for {kind}: {value}", severity="low" if removed else "medium",
                      confidence="low", category="defender", mitre=["T1562.001"],
                      evidence={"type": kind, "value": value, "added": util.iso(e["time"]), "later_removed": removed},
                      description="Defender stopped scanning this location. Development tools add exclusions; so does "
                                  "malware, for the folder it runs from." + (" It was removed again afterwards." if removed else ""),
                      remediation="Windows Security > Virus & threat protection > Manage settings > Exclusions.")
            m = _DEFENDER_DISABLE.search(new)
            if m:
                value = int(m.group(1), 16)
                setting = m.group(0).split("=")[0].strip().split("\\")[-1]
                weakened = value != 0 if "disable" in setting.lower() else value in (0, 4) if "tamper" in setting.lower() else value == 0
                if weakened:
                    b.add(("evt.defender.setting_weakened", setting.lower(), value), e["time"], rule="evt.defender.setting_weakened",
                          title=f"A Defender protection setting was turned down: {setting}", severity="high", confidence="medium",
                          category="defender", mitre=["T1562.001"],
                          evidence={"old": util.truncate(old, 300), "new": util.truncate(new, 300), "when": util.iso(e["time"])},
                          description="This registry value controls part of Defender's protection and was changed to the weaker setting.")
        elif e["id"] == 3002:
            b.add(("evt.defender.rtp_failure",), e["time"], rule="evt.defender.rtp_failure", title="Defender real-time protection reported a failure",
                  severity="medium", confidence="low", category="defender", evidence={k: util.truncate(v, 200) for k, v in d.items()},
                  description="A component of real-time protection failed and may not have been protecting the PC.")


def _powershell(b: _Bucket, blocks: list[dict], classic: list[dict], own_marker: str) -> None:
    for e in blocks:
        d = e["data"]
        text = d.get("ScriptBlockText") or ""
        path = d.get("Path") or ""
        if own_marker and own_marker in path.lower():
            continue
        _text_hits(b, text, "script", "evt.ps.", "PowerShell ran a script that: {what}", e["time"],
                   {"script_file": path or "(typed or passed on the command line)", "ran": util.iso(e["time"]),
                    "excerpt": util.truncate(text.strip(), 700)}, (path.lower(), text[:160]), ("T1059.001",),
                   "Windows recorded the script text when it ran.")
    for e in classic:
        m = _HOST_APP.search(e["data"].get("p2") or "")
        if not m:
            continue
        host = m.group(1).strip()
        if own_marker and own_marker in host.lower():
            continue
        flags = cl.powershell_flags(host)
        ev = {"command_line": util.truncate(host, 1200), "ran": util.iso(e["time"])}
        if flags.get("decoded"):
            ev["decoded_command"] = util.truncate(flags["decoded"], 1200)
        hits = _text_hits(b, host, "cmdline", "evt.pscmd.", "PowerShell was started with a command that: {what}", e["time"], ev,
                          (host[:240],), ("T1059.001",), "Recovered from the PowerShell engine log, so it is visible even "
                          "though the process has exited.")
        if not hits and flags.get("decoded") and flags.get("hidden"):
            b.add(("evt.pscmd.hidden_encoded", (flags["decoded"] or "")[:200]), e["time"], rule="evt.pscmd.hidden_encoded",
                  title="PowerShell was started hidden with an encoded command", severity="medium", confidence="medium",
                  mitre=["T1059.001", "T1027"], evidence=ev,
                  description="Hidden window plus base64-encoded script. The decoded script is attached and matched no attack pattern.")


def _wmi(b: _Bucket, events: list[dict]) -> None:
    for e in events:
        d = e["data"]
        consumer = d.get("CONSUMER") or ""
        if "SCM Event Log Consumer" in consumer or "BVTConsumer" in consumer:
            continue
        cause = d.get("PossibleCause") or ""
        active = "CommandLineEventConsumer" in consumer or "ActiveScriptEventConsumer" in consumer
        b.add(("evt.wmi.subscription", consumer.lower()), e["time"], rule="evt.wmi.subscription",
              title=f"A permanent WMI event subscription was registered: {util.truncate(consumer, 80)}",
              severity="high" if active else "medium", confidence="medium", mitre=["T1546.003"],
              evidence={"consumer": consumer, "filter": d.get("ESS"), "namespace": d.get("Namespace"),
                        "definition": util.truncate(cause, 1500), "when": util.iso(e["time"])},
              description="WMI subscriptions run a command or script whenever their trigger fires, as SYSTEM, with no "
                          "file in the usual autorun places.")


def _bits(b: _Bucket, events: list[dict]) -> None:
    hosts: dict[str, int] = defaultdict(int)
    for e in events:
        url = e["data"].get("url") or ""
        m = re.match(r"^(https?)://([^/:]+)", url, re.I)
        if not m:
            continue
        hosts[m.group(2).lower()] += 1
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", m.group(2)) and util.is_public_ip(m.group(2)):
            b.add(("evt.bits.bare_ip", m.group(2)), e["time"], rule="evt.bits.bare_ip",
                  title=f"A background transfer downloaded from a bare IP address: {m.group(2)}", severity="medium",
                  confidence="low", mitre=["T1197", "T1105"], evidence={"url": util.truncate(url, 400), "job": e["data"].get("name")},
                  entity={"type": "ip", "ip": m.group(2)}, actions=["block_ip"],
                  description="Update services use named hosts. A raw IP address is unusual for a BITS job.")


def _firewall(b: _Bucket, events: list[dict]) -> None:
    for e in events:
        d = e["data"]
        if e["id"] in (2004, 2071, 2097, 2005, 2073, 2099):
            if d.get("Direction") != "1" or d.get("Action") != "3" or d.get("Active") == "0":
                continue
            app = d.get("ApplicationPath") or ""
            mod = d.get("ModifyingApplication") or ""
            ports = set((d.get("LocalPorts") or "").replace(" ", "").split(","))
            zone = util.path_zone(app) if app else None
            ev = {"rule": d.get("RuleName"), "program": app, "local_ports": d.get("LocalPorts"), "protocol": d.get("Protocol"),
                  "remote_addresses": d.get("RemoteAddresses"), "added_by": mod, "added_by_account": d.get("ModifyingUser"),
                  "when": util.iso(e["time"])}
            if zone in util.HIGH_RISK:
                b.add(("evt.fw.inbound_temp", app.lower()), e["time"], rule="evt.fw.inbound_temp",
                      title=f"The firewall was opened for a program in a temporary folder: {util.basename(app)}", severity="medium",
                      confidence="medium", mitre=["T1562.004"], evidence=ev, entity={"type": "file", "path": app},
                      description="An inbound allow rule lets other machines connect to this program. Programs in Temp, "
                                  "Downloads or Public are rarely meant to be servers.")
            elif ports & _ADMIN_PORTS and util.basename(mod) in ("netsh.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "reg.exe"):
                b.add(("evt.fw.admin_port", ",".join(sorted(ports))), e["time"], rule="evt.fw.admin_port",
                      title=f"A script opened the firewall for remote-administration port(s) {d.get('LocalPorts')}", severity="medium",
                      confidence="medium", mitre=["T1562.004", "T1021"], evidence=ev,
                      description="The rule was added from a command line, not by the Settings app or an installer.")
        elif e["id"] == 2003:
            if d.get("SettingType") == "1" and (d.get("SettingValueString") or "").lower() in ("no", "false", "0"):
                b.add(("evt.fw.disabled", d.get("Profiles")), e["time"], rule="evt.fw.disabled",
                      title="Windows Firewall was turned off for a network profile", severity="high", confidence="medium",
                      mitre=["T1562.004"], evidence={"profile": d.get("Profiles"), "by": d.get("ModifyingApplication"),
                                                     "when": util.iso(e["time"])},
                      description="The current state is reported separately; this records when it was switched off and by what.")


def _rdp(b: _Bucket, events: list[dict]) -> None:
    seen_users: dict[tuple, set] = defaultdict(set)
    for e in sorted(events, key=lambda x: x["time"] or 0):
        d = e["data"]
        addr = (d.get("Address") or d.get("Param3") or "").strip()
        user = d.get("User") or "\\".join(x for x in (d.get("Param2"), d.get("Param1")) if x)
        if not addr or addr.upper() == "LOCAL" or util.is_loopback(addr):
            continue
        day = time.strftime("%Y-%m-%d", time.localtime(e["time"] or 0))
        seen_users[(addr, day)].add(user)
        user = ", ".join(sorted(seen_users[(addr, day)]))
        public = util.is_public_ip(addr)
        overlay = util.is_mesh_vpn_ip(addr)
        where = ("The source is an internet address. " if public else
                 "The source is in the 100.64.0.0/10 range that Tailscale and similar mesh VPNs hand out, so it is "
                 "probably one of your own devices. " if overlay else "The source is on your local or private network. ")
        b.add(("evt.rdp.logon", addr, day), e["time"], rule="evt.rdp.logon",
              title=f"Remote Desktop session from {addr} on {day}", severity="high" if public else "medium",
              confidence="medium", category="eventlog", mitre=["T1021.001"], entity={"type": "ip", "ip": addr}, actions=["block_ip"],
              evidence={"source": addr, "accounts": user, "internet_address": public, "mesh_vpn_range": overlay},
              description=where + "If this was not you connecting from another device, someone else has your password.")


def _security(b: _Bucket, events: list[dict]) -> None:
    fails: dict[str, list] = defaultdict(list)
    success_src: set[str] = set()
    for e in events:
        d = e["data"]
        if e["id"] == 1102:
            b.add(("evt.log_cleared", "security", int(e["time"] or 0)), e["time"], rule="evt.log_cleared",
                  title="The Security log was cleared", severity="high", confidence="medium", mitre=["T1070.001"],
                  evidence={"by": d.get("SubjectUserName"), "when": util.iso(e["time"])},
                  description="Clearing the audit log removes the record of logons and account changes.")
        elif e["id"] == 4720:
            b.add(("evt.account.created", (d.get("TargetUserName") or "").lower()), e["time"], rule="evt.account.created",
                  title=f"A user account was created: {d.get('TargetUserName')}", severity="medium", confidence="low", category="account",
                  mitre=["T1136.001"], evidence={"account": d.get("TargetUserName"), "by": d.get("SubjectUserName"), "when": util.iso(e["time"])},
                  entity={"type": "account", "name": d.get("TargetUserName") or ""}, actions=["disable_user"],
                  description="Confirm that you or software you installed created it.")
        elif e["id"] in (4732, 4728, 4756):
            sid = d.get("TargetSid") or ""
            if sid in ("S-1-5-32-544", "S-1-5-32-555", "S-1-5-32-580"):
                b.add(("evt.account.privileged_group", sid, d.get("MemberSid")), e["time"], rule="evt.account.privileged_group",
                      title=f"An account was added to {d.get('TargetUserName')}", severity="high", confidence="medium", category="account",
                      mitre=["T1098"], evidence={"member_sid": d.get("MemberSid"), "member": d.get("MemberName"),
                                                 "by": d.get("SubjectUserName"), "when": util.iso(e["time"])},
                      description="Membership of this group gives administrator or remote-logon rights.")
        elif e["id"] in (4698, 4697):
            content = d.get("TaskContent") or d.get("ServiceFileName") or ""
            if "<Command>" in content:
                pairs = re.findall(r"<Command>(.*?)</Command>|<Arguments>(.*?)</Arguments>", content, re.S)
                cmds = html.unescape(" ".join(x for pair in pairs for x in pair if x))
            else:
                cmds = content
            name = d.get("TaskName") or d.get("ServiceName") or ""
            _text_hits(b, cmds, "cmdline", "evt.created.", "A task or service was created that runs: {what}", e["time"],
                       {"name": name, "by": d.get("SubjectUserName"), "command": util.truncate(cmds, 800)}, (name.lower(), cmds[:200]),
                       ("T1053.005",), "Recorded by the Security log when it was registered.")
        elif e["id"] == 4719:
            b.add(("evt.audit_policy_changed", int((e["time"] or 0) // 3600)), e["time"], rule="evt.audit_policy_changed",
                  title="The audit policy was changed", severity="medium", confidence="low", mitre=["T1562.002"],
                  evidence={"by": d.get("SubjectUserName"), "subcategory": d.get("SubcategoryGuid"), "changes": d.get("AuditPolicyChanges")},
                  description="Changing what Windows logs is a way to stop leaving evidence.")
        elif e["id"] == 4625:
            src = (d.get("IpAddress") or "").strip("-") or d.get("WorkstationName") or "local"
            fails[src].append(e)
        elif e["id"] == 4624:
            ip = (d.get("IpAddress") or "").strip("-")
            if not ip or util.is_loopback(ip):
                continue
            success_src.add(ip)
            ltype = d.get("LogonType")
            public = util.is_public_ip(ip)
            if ltype == "10" or public:
                b.add(("evt.logon.remote", ip, (d.get("TargetUserName") or "").lower(), ltype), e["time"], rule="evt.logon.remote",
                      title=f"{'Remote Desktop' if ltype == '10' else 'Network'} logon from {ip} as {d.get('TargetUserName')}",
                      severity="high" if public else "medium", confidence="medium", mitre=["T1078", "T1021"],
                      entity={"type": "ip", "ip": ip}, actions=["block_ip"],
                      evidence={"source": ip, "user": d.get("TargetUserName"), "logon_type": ltype, "workstation": d.get("WorkstationName"),
                                "auth": d.get("AuthenticationPackageName")},
                      description="Someone logged on to this PC from another machine with valid credentials.")
        elif e["id"] == 4688:
            cmdl = d.get("CommandLine") or ""
            if cmdl:
                _text_hits(b, cmdl, "cmdline", "evt.proc.", "A process ran that: {what}", e["time"],
                           {"command_line": util.truncate(cmdl, 1200), "image": d.get("NewProcessName"), "parent": d.get("ParentProcessName"),
                            "user": d.get("SubjectUserName"), "ran": util.iso(e["time"])}, (cmdl[:240],), (),
                           "Recorded by process-creation auditing, so it is visible although the process has exited.")
    for src, evs in fails.items():
        if len(evs) < 15:
            continue
        users = sorted({x["data"].get("TargetUserName") or "" for x in evs})[:8]
        hit = src in success_src
        b.add(("evt.logon.bruteforce", src), max(x["time"] or 0 for x in evs), rule="evt.logon.bruteforce",
              title=f"{len(evs)} failed logons from {src}" + (" followed by a successful one" if hit else ""),
              severity="critical" if hit and util.is_public_ip(src) else "high" if hit or util.is_public_ip(src) else "medium",
              confidence="medium", mitre=["T1110"], entity={"type": "ip", "ip": src} if re.match(r"^[0-9a-f:.]+$", src, re.I) else {},
              actions=["block_ip"] if re.match(r"^[0-9a-f:.]+$", src, re.I) else [],
              evidence={"source": src, "failed": len(evs), "accounts_tried": users, "succeeded_from_same_source": hit},
              description="Many failed logons from one source is password guessing.")


def _sysmon(b: _Bucket, events: list[dict]) -> None:
    benign_src = ("\\msmpeng.exe", "\\csrss.exe", "\\svchost.exe", "\\wininit.exe", "\\lsm.exe", "\\services.exe", "\\mssense.exe",
                  "\\taskmgr.exe", "\\procexp64.exe", "\\wmiprvse.exe", "\\nissrv.exe", "\\mpdefendercoreservice.exe")
    for e in events:
        d = e["data"]
        if e["id"] == 1:
            cmdl = d.get("CommandLine") or ""
            _text_hits(b, cmdl, "cmdline", "evt.proc.", "A process ran that: {what}", e["time"],
                       {"command_line": util.truncate(cmdl, 1200), "image": d.get("Image"), "parent": d.get("ParentImage"),
                        "parent_command_line": util.truncate(d.get("ParentCommandLine"), 400), "user": d.get("User"),
                        "hashes": d.get("Hashes"), "ran": util.iso(e["time"])}, (cmdl[:240],), (), "Recorded by Sysmon.")
        elif e["id"] == 10:
            target = (d.get("TargetImage") or "").lower()
            source = (d.get("SourceImage") or "").lower()
            try:
                access = int(d.get("GrantedAccess") or "0", 16)
            except ValueError:
                access = 0
            if target.endswith("\\lsass.exe") and access & 0x10 and not source.endswith(benign_src):
                b.add(("evt.sysmon.lsass_read", source), e["time"], rule="evt.sysmon.lsass_read",
                      title=f"{util.basename(source)} opened the credential store's memory for reading", severity="high", confidence="medium",
                      mitre=["T1003.001"], entity={"type": "file", "path": d.get("SourceImage") or ""},
                      evidence={"source": d.get("SourceImage"), "access": d.get("GrantedAccess"), "call_trace": util.truncate(d.get("CallTrace"), 400)},
                      description="Reading lsass.exe memory is how passwords and hashes are stolen.")
        elif e["id"] == 8:
            source = (d.get("SourceImage") or "").lower()
            if source.endswith(benign_src):
                continue
            b.add(("evt.sysmon.remote_thread", source, (d.get("TargetImage") or "").lower()), e["time"], rule="evt.sysmon.remote_thread",
                  title=f"{util.basename(source)} started a thread inside {util.basename(d.get('TargetImage') or '')}", severity="medium",
                  confidence="low", mitre=["T1055"], evidence={"source": d.get("SourceImage"), "target": d.get("TargetImage"),
                                                               "start_module": d.get("StartModule"), "start_function": d.get("StartFunction")},
                  description="Creating a thread in another process is the basic move of code injection. Debuggers, "
                              "accessibility tools and some drivers do it too.")
        elif e["id"] == 25:
            b.add(("evt.sysmon.process_tampering", (d.get("Image") or "").lower()), e["time"], rule="evt.sysmon.process_tampering",
                  title=f"A process image was replaced in memory: {util.basename(d.get('Image') or '')}", severity="high", confidence="medium",
                  mitre=["T1055.012"], evidence={"image": d.get("Image"), "type": d.get("Type"), "user": d.get("User")},
                  description="What runs in memory is not what is on disk: process hollowing or a related technique.")


def detect(facts: dict, ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    ev = facts.get("events") or {}
    own = (ctx.get("own_marker") or "").lower()
    b = _Bucket()
    _system(b, ev.get("System") or [])
    _defender(b, ev.get(logs.DEFENDER) or [])
    _powershell(b, ev.get(logs.POWERSHELL) or [], ev.get(logs.PS_CLASSIC) or [], own)
    _wmi(b, ev.get(logs.WMI) or [])
    _bits(b, ev.get(logs.BITS) or [])
    _firewall(b, ev.get(logs.FIREWALL) or [])
    _rdp(b, (ev.get(logs.RDP_LSM) or []) + (ev.get(logs.RDP_RCM) or []))
    _security(b, ev.get("Security") or [])
    _sysmon(b, ev.get(logs.SYSMON) or [])
    out = b.findings()
    for f in out:  # the same thing many times over is stronger evidence that it is scheduled, not a one-off
        if f.evidence.get("times", 1) >= 20 and SEV_ORDER[f.severity] == SEV_ORDER["medium"] and f.rule.startswith("evt.ps"):
            f.tags.append("recurring")
    return out
