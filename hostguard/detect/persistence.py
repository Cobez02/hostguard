"""Rules over autorun entries (see collect.persistence for the entry format)."""

from __future__ import annotations

import os
import re

from .. import paths, sigs, util, winapi
from ..model import Finding, SEV_ORDER, bump
from . import cmdline as cl
from .processes import SYSTEM_IMAGES

_S32 = paths.SYSTEM32.lower()
ACCESSIBILITY = {"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe",
                 "atbroker.exe"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe"}
SHELL_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
               "regsvr32.exe", "msiexec.exe", "conhost.exe", "forfiles.exe", "pcalua.exe"}
BENIGN_DEBUGGERS = ("procexp", "systeminformer", "processhacker", "vsjitdebugger", "drwtsn32", "windbg", "taskmgr")
LSA_KNOWN = {"Authentication Packages": {"msv1_0"},
             "Security Packages": {"kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "livessp",
                                   "negoexts", "negotiate", "credssp"},
             "Notification Packages": {"scecli", "rassfm"}}
PRINT_MONITORS = {"localspl.dll", "tcpmon.dll", "usbmon.dll", "wsdmon.dll", "appmon.dll", "fxsmon.dll", "inetpp.dll",
                  "win32spl.dll", "apmon.dll"}
TIME_PROVIDERS = {"w32time.dll", "vmictimeprovider.dll"}
# Drivers that are signed and legitimate but give any administrator-level program kernel access.
# Attackers bring them along to switch off security software ("bring your own vulnerable driver").
ABUSABLE_DRIVERS = {"rtcore64.sys", "rtcore32.sys", "gdrv.sys", "dbutil_2_3.sys", "dbutildrv2.sys", "mhyprot2.sys",
                    "iqvw64e.sys", "kprocesshacker.sys", "aswarpot.sys", "zamguard64.sys", "zam64.sys",
                    "truesight.sys", "viragt64.sys", "capcom.sys", "naldrv.sys", "winring0x64.sys", "winring0.sys",
                    "procexp152.sys", "asrdrv104.sys", "atillk64.sys", "bs_def64.sys", "ene.sys", "wnbios.sys",
                    "physmem.sys", "kdu.sys", "ksapi64.sys", "tfsysmon.sys", "wsftprm.sys", "probmon.sys"}
# Vendor delivery networks that browser and Windows updaters fetch from over plain HTTP (the
# payload is verified by hash or signature after download).
_UPDATE_HOSTS = re.compile(r"^http://[a-z0-9.-]*\.(?:microsoft\.com|windowsupdate\.com|msedge\.net|gvt1\.com|google\.com|"
                           r"googleapis\.com|mozilla\.net|mozilla\.org|adobe\.com)(?::\d+)?/", re.I)
_SCRIPT_PATH = re.compile(r'"?([a-z]:\\[^"|<>*?\r\n]+?\.(?:ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta|py))"?(?=\s|$)', re.I)
_KIND_LABEL = {"run_key": "Registry autorun", "startup_folder": "Startup folder item", "task": "Scheduled task",
               "service": "Service", "driver": "Driver", "active_setup": "Active Setup entry",
               "bits_job": "Background transfer job", "wmi_subscription": "WMI event subscription",
               "windows_load": "Legacy load entry", "logon_script": "Logon script", "cmd_autorun": "Command Prompt autorun",
               "winlogon": "Winlogon entry", "com_hijack": "Per-user COM class", "ps_profile": "PowerShell profile"}
_MITRE = {"run_key": "T1547.001", "startup_folder": "T1547.001", "task": "T1053.005", "service": "T1543.003",
          "driver": "T1543.003", "active_setup": "T1547.014", "bits_job": "T1197", "wmi_subscription": "T1546.003",
          "winlogon": "T1547.004", "com_hijack": "T1546.015", "ps_profile": "T1546.013", "logon_script": "T1037.001",
          "windows_load": "T1547.001", "cmd_autorun": "T1546"}
_GENERIC = {"run_key", "startup_folder", "task", "service", "driver", "active_setup", "windows_load", "logon_script",
            "cmd_autorun", "wmi_subscription", "bits_job"}


def paths_to_check(entries: list[dict]) -> set[str]:
    """Every file whose signature the rules will ask about."""
    out: set[str] = set()
    for e in entries:
        if e.get("image"):
            out.add(e["image"])
        dll = e.get("meta", {}).get("service_dll")
        if dll:
            out.add(dll)
        d = _rundll_target(e)
        if d:
            out.add(d)
    return out


def _rundll_target(e: dict) -> str:
    if util.basename(e.get("image", "")) != "rundll32.exe" or not e.get("args"):
        return ""
    first = e["args"].strip()
    target = first[1:first.find('"', 1)] if first.startswith('"') and first.find('"', 1) > 0 else first.split(",")[0].split()[0]
    target = target.split(",")[0]
    return util.resolve_image(target if target.lower().endswith((".dll", ".cpl", ".ocx")) else target + ".dll")


def _entity(e: dict) -> dict:
    ent = {"type": "autorun", "kind": e["kind"], "location": e["location"], "name": e["name"],
           "command": e.get("command", ""), "path": e.get("image", "")}
    for k in ("file", "service_dll"):
        if e.get("meta", {}).get(k):
            ent[k] = e["meta"][k]
    return ent


def _evidence(e: dict, sig: dict | None) -> dict:
    ev = {"where": e["location"], "name": e["name"], "command": util.truncate(e.get("command"), 1200),
          "program": e.get("image"), "signature": sigs.describe(sig) if e.get("image") else None}
    for k, v in e.get("meta", {}).items():
        if k in ("content",):
            continue
        if k in ("modified",) and isinstance(v, (int, float)):
            v = util.iso(v)
        ev[k] = v
    return {k: v for k, v in ev.items() if v not in (None, "", [], False)}


def _actions(e: dict) -> list[str]:
    acts = ["disable_autorun"]
    if e.get("image") and util.path_zone(e["image"]) in util.USER_WRITABLE:
        acts.append("quarantine")
    return acts


def _read_script(path: str, limit: int = 262144) -> str:
    try:
        with open(path, "rb") as f:
            raw = f.read(limit)
    except OSError:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8", "replace")


def detect(facts: dict, sig_map: dict[str, dict], ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    own = (ctx.get("own_marker") or "").lower()
    out: list[Finding] = []

    def add(e, sig, rule, title, sev, conf, desc, mitre=None, key_extra=(), extra=None, remediation="", tags=(),
            actions=None, category="persistence"):
        ev = _evidence(e, sig)
        if extra:
            ev.update(extra)
        if e.get("meta", {}).get("disabled") and SEV_ORDER[sev] > SEV_ORDER["low"]:
            sev = "low"
            tags = (*tags, "disabled")
        out.append(Finding(rule=rule, title=title, severity=sev, confidence=conf, category=category,
                           description=desc, evidence=ev, entity=_entity(e),
                           mitre=list(mitre or ([_MITRE[e["kind"]]] if e["kind"] in _MITRE else [])),
                           actions=_actions(e) if actions is None else list(actions), collector="persistence",
                           remediation=remediation, tags=list(tags),
                           key_parts=(e["kind"], e["location"], e["name"], *key_extra)))

    unquoted: list[str] = []
    for e in facts.get("entries") or []:
        kind, name, cmd, image = e["kind"], e["name"], e.get("command") or "", e.get("image") or ""
        meta = e.get("meta", {})
        if own and own in cmd.lower():
            continue
        base = util.basename(image)
        zone = util.path_zone(image) if image else None
        sig = sigs.lookup(sig_map, image)
        label = _KIND_LABEL.get(kind, kind)
        ms_task = kind == "task" and name.lower().startswith("\\microsoft\\")

        if kind in _GENERIC:
            # ---- what the entry runs
            hits = cl.analyse_command(cmd) if cmd else []
            flags = cl.powershell_flags(cmd) if cmd else {}
            for h in hits:
                sev = h.rule.severity if SEV_ORDER[h.rule.severity] >= SEV_ORDER["high"] else bump(h.rule.severity)
                extra = {"matched": h.match, "urls": cl.urls_in(cmd + " " + (flags.get("decoded") or ""))}
                if h.decoded:
                    extra["decoded_command"] = util.truncate(flags.get("decoded"), 1500)
                add(e, sig, "persist." + h.rule.id, f"{label} runs on its own: {h.rule.title.lower()}", sev, "high",
                    (h.rule.why + " " if h.rule.why else "") + "Here it is wired to start automatically, so it "
                    "comes back after every restart.", list(h.rule.mitre) + [_MITRE.get(kind, "T1547")],
                    key_extra=(h.match[:80],), extra=extra)
            if flags.get("decoded") and not hits:
                add(e, sig, "persist.ps.encoded", f"{label} runs an encoded PowerShell command", "medium", "medium",
                    "The command is base64-encoded. The decoded script is attached; nothing in it matched an attack "
                    "pattern, but there is rarely a good reason to hide an autorun's command.",
                    ["T1027", _MITRE.get(kind, "T1547")], extra={"decoded_command": util.truncate(flags["decoded"], 1500)})

            # ---- scripts the entry points at
            script_hits = False
            for m in _SCRIPT_PATH.finditer(os.path.expandvars(cmd)):
                script = m.group(1)
                if util.path_zone(script) not in util.USER_WRITABLE:
                    continue
                text = _read_script(script)
                found = cl.match_text(text, "script") if text else []
                for h in found:
                    script_hits = True
                    add(e, sig, "persist.script." + h.rule.id, f"{label} runs a script that {h.rule.title.lower()}",
                        bump(h.rule.severity) if SEV_ORDER[h.rule.severity] < SEV_ORDER["high"] else h.rule.severity,
                        "high", f"The script {script} starts automatically and contains this pattern.",
                        list(h.rule.mitre) + [_MITRE.get(kind, "T1547")], key_extra=(script, h.rule.id),
                        extra={"script": script, "matched": h.match})
                if not found and base in SCRIPT_HOSTS | {"powershell.exe", "pwsh.exe", "cmd.exe"} and not ms_task:
                    exists = os.path.isfile(script)
                    sev = "medium" if (base in SCRIPT_HOSTS or util.path_zone(script) in util.HIGH_RISK) else "low"
                    add(e, sig, "persist.script_autorun", f"{label} runs a script from a user-writable folder: "
                        f"{os.path.basename(script)}", sev if exists else "low", "low",
                        "Any program running as you can rewrite this script, and it will run again at the next "
                        "trigger. Its current contents matched no attack pattern." if exists else
                        "The script it points to no longer exists.", key_extra=(script,), extra={"script": script})
                    script_hits = True
            if base in SCRIPT_HOSTS and not hits and not script_hits and not ms_task:
                add(e, sig, "persist.script_host", f"{label} starts through {base}", "medium", "medium",
                    "Script hosts run code that antivirus sees only at run time. Autoruns rarely need one.",
                    ["T1059", _MITRE.get(kind, "T1547")])

            # ---- rundll32 payloads
            dll = _rundll_target(e)
            if dll and not ms_task:
                dsig = sigs.lookup(sig_map, dll)
                dzone = util.path_zone(dll)
                if sigs.lacks_trust(dsig) and dzone in util.USER_WRITABLE:
                    add(e, dsig, "persist.rundll32_unsigned", f"{label} loads an unsigned DLL through rundll32", "high",
                        "medium", f"rundll32.exe is a Windows program, so the autorun looks harmless, but the code "
                        f"it runs is {dll}.", ["T1218.011", _MITRE.get(kind, "T1547")], extra={"dll": dll})

            # ---- the program itself
            if image and sig and base not in SHELL_HOSTS:
                if sig["status"] == "Missing":
                    if kind in ("run_key", "startup_folder", "task") and not ms_task:
                        add(e, sig, "persist.missing_target", f"{label} points to a file that no longer exists: {name}",
                            "info", "low", "A leftover from uninstalled software, or what remains after something "
                            "deleted itself.", actions=["disable_autorun"])
                elif sigs.is_tampered(sig):
                    add(e, sig, "persist.tampered_target", f"{label} runs a file modified after signing: {base}", "high",
                        "high", "The file's publisher signature no longer matches its contents.", ["T1554"])
                elif sigs.lacks_trust(sig) and zone in util.USER_WRITABLE:
                    sev = "medium"
                    why = "It starts automatically, nobody signed it, and it sits where any program can replace it."
                    if zone in util.HIGH_RISK:
                        sev = "high"
                    if kind in ("service", "driver") or (kind == "task" and meta.get("runlevel") == "Highest") \
                            or (kind == "task" and str(meta.get("user", "")).upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM")):
                        sev = "high"
                        why += " It also runs with administrator or SYSTEM rights, so replacing the file is a way to take over the PC."
                    add(e, sig, "persist.unsigned_user_writable", f"{label} runs an unsigned program from a "
                        f"user-writable folder: {base}", sev, "medium", why, tags=("unsigned",))
                if base in SYSTEM_IMAGES and zone != "windows" and sig["status"] != "Missing" \
                        and not sigs.is_microsoft(sig):
                    add(e, sig, "persist.masquerade", f"{label} runs a program named like a Windows component: {base}",
                        "high", "high", f"{base} belongs in the Windows folder. This copy is at {image}.",
                        ["T1036.005", _MITRE.get(kind, "T1547")])
                product = cl.remote_tool(base)
                if product and kind in ("run_key", "startup_folder", "task", "service"):
                    add(e, sig, "persist.remote_access_tool", f"Remote access software starts automatically: {product}",
                        "low" if zone not in util.USER_WRITABLE else "medium", "low",
                        "It will be reachable after every restart. Fine if you set it up; worth removing if not.",
                        ["T1219"], key_extra=(product,))
            if kind == "task" and meta.get("runlevel") == "Highest" and zone in util.USER_WRITABLE and image \
                    and sigs.is_valid(sig) and winapi.can_replace(image):
                add(e, sig, "persist.task.elevated_user_writable", f"Elevated task runs a program any process can replace: {base}",
                    "medium", "medium", "The task runs with administrator rights without a UAC prompt, but the "
                    "program lives in a folder that does not need administrator rights to write to.", ["T1053.005", "T1548"])

        # ---- kind-specific rules
        if kind == "task" and meta.get("user_override") and image:
            if sigs.lacks_trust(sig):
                add(e, sig, "persist.task.com_hijack", f"Scheduled task's COM handler is overridden for your account: {name}",
                    "high", "high", "A per-user registry entry replaces the component this task loads. The task "
                    "itself looks untouched, which is the point.", ["T1546.015", "T1053.005"])
        elif kind == "service":
            raw = meta.get("raw_image_path", "")
            if base in {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"} \
                    or raw.lower().startswith("%comspec%"):
                pipe = "\\\\.\\pipe\\" in raw.lower()
                add(e, sig, "persist.service.shell", f"Service runs a shell command: {name}", "critical" if pipe else "high",
                    "high", "Services start as SYSTEM. One whose program is a shell is how remote-execution and "
                    "privilege-escalation tools run commands" + (", and this one writes to a named pipe, the "
                    "signature of a get-SYSTEM trick." if pipe else "."), ["T1569.002", "T1543.003"])
            dll = meta.get("service_dll")
            if dll:
                dsig = sigs.lookup(sig_map, dll)
                if sigs.lacks_trust(dsig) and util.path_zone(dll) != "program_files":
                    add(e, dsig, "persist.service.dll_unsigned", f"Service loads an unsigned DLL: {name}", "high", "medium",
                        f"The service's code is {dll}, hosted inside a Windows svchost process.", ["T1543.003"],
                        extra={"service_dll": dll})
            fail = meta.get("failure_command", "")
            if fail and (cl.analyse_command(fail) or util.basename(util.split_command(fail)[0]) in SHELL_HOSTS):
                add(e, sig, "persist.service.failure_command", f"Service runs a command when it fails: {name}", "medium",
                    "medium", "A recovery command is a quiet way to get code run as SYSTEM.", ["T1543.003"],
                    extra={"failure_command": fail})
            if raw and not raw.startswith('"') and " " in image and zone not in ("windows",) \
                    and not raw.lower().startswith(("\\systemroot", "system32", "\\??\\")):
                unquoted.append(f"{name}: {raw}")
        elif kind == "driver":
            if base in ABUSABLE_DRIVERS:
                add(e, sig, "persist.driver.abusable", f"Driver with known kernel-access weaknesses is installed: {base}",
                    "medium", "low", "Hardware and tuning utilities ship drivers like this one. Attackers load the "
                    "same drivers to disable security software, so one you cannot account for deserves a look.",
                    ["T1068", "T1562.001"], actions=[])
            low = image.lower()
            standard = low.startswith((_S32 + "\\drivers\\", _S32 + "\\driverstore\\")) or zone == "program_files"
            if image and sig and sig["status"] not in ("Missing",) and not standard and zone in util.USER_WRITABLE:
                add(e, sig, "persist.driver.odd_location", f"Kernel driver registered from a user-writable folder: {base}",
                    "high", "medium", "Drivers belong in the Windows driver folders. Loaders that bring a vulnerable "
                    "driver along drop it wherever they can write.", ["T1543.003", "T1068"])
        elif kind == "winlogon":
            val = cmd.strip().lower()
            ok = (name == "Shell" and e["location"].startswith("HKLM") and val == "explorer.exe") \
                or (name == "Userinit" and val.rstrip(",") in (_S32 + "\\userinit.exe", "userinit.exe")) \
                or (name == "VmApplet" and val.startswith("systempropertiesperformance.exe"))
            if not ok:
                add(e, sig, "persist.winlogon", f"Winlogon {name} was changed", "critical", "high",
                    "This value decides what runs at every logon. Windows sets it to explorer.exe and userinit.exe "
                    "and almost nothing legitimate changes it.", ["T1547.004"])
        elif kind == "windows_load":
            add(e, sig, "persist.windows_load", f"Legacy '{name}' autorun value is set", "high", "medium",
                "A holdover from Windows 3.x that still works and that almost nothing legitimate uses.", ["T1547.001"])
        elif kind == "appinit_dlls":
            add(e, sig, "persist.appinit_dlls", "A DLL is set to load into every program (AppInit_DLLs)",
                "high" if meta.get("enabled") else "medium", "medium",
                "Every program that loads user32.dll will load this DLL. Secure Boot switches the mechanism off, "
                "but the entry shows something tried to use it.", ["T1546.010"])
        elif kind == "appcert_dlls":
            add(e, sig, "persist.appcert_dlls", "A DLL is set to load into every new process (AppCertDlls)", "high", "high",
                "Almost never set on a clean PC.", ["T1546.009"])
        elif kind == "ifeo_debugger":
            target = (meta.get("target_image") or "").lower()
            dbg = util.basename(image)
            if target in ACCESSIBILITY:
                add(e, sig, "persist.ifeo.accessibility", f"Lock-screen backdoor: {target} is redirected to {dbg}",
                    "critical", "high", "Pressing the accessibility shortcut on the logon screen now runs this "
                    "program as SYSTEM, without logging in.", ["T1546.008", "T1546.012"])
            elif any(b in dbg for b in BENIGN_DEBUGGERS):
                add(e, sig, "persist.ifeo.debugger_tool", f"{target} is redirected to {dbg}", "info", "low",
                    "A debugger or Task Manager replacement registered itself. Expected if you installed it.",
                    ["T1546.012"])
            else:
                add(e, sig, "persist.ifeo.debugger", f"Starting {target} runs {dbg} instead", "high", "medium",
                    "The 'Debugger' value makes Windows launch another program whenever this one starts. Malware "
                    "uses it to hijack a program or to stop security tools from running.", ["T1546.012"])
        elif kind == "ifeo_silent_exit":
            add(e, sig, "persist.ifeo.silent_exit", f"A program runs whenever {meta.get('target_image')} exits", "high",
                "medium", "Silent process exit monitoring launches a command when the watched program closes.",
                ["T1546.012"])
        elif kind == "boot_execute":
            if not (name == "BootExecute" and cmd.lower().startswith("autocheck ")):
                add(e, sig, "persist.boot_execute", f"Session Manager {name} runs: {util.truncate(cmd, 80)}", "high", "medium",
                    "Programs listed here run before Windows finishes starting, ahead of any security software.",
                    ["T1547.001"])
        elif kind == "lsa_package":
            pkg = cmd.lower().removesuffix(".dll")
            if pkg and pkg not in LSA_KNOWN.get(name, set()):
                ms = sigs.is_microsoft(sig)
                add(e, sig, "persist.lsa_package", f"Extra LSA {name.lower()[:-1]}: {cmd}",
                    "low" if ms else "high" if sigs.lacks_trust(sig) else "medium", "medium", "Packages listed here are loaded into the process that handles every logon and can "
                    "see passwords in clear text." + (" This one is signed by Microsoft." if ms else ""),
                    ["T1547.002", "T1547.005", "T1556.002"])
        elif kind in ("print_monitor", "netsh_helper", "time_provider", "network_provider"):
            known = (kind == "print_monitor" and base in PRINT_MONITORS) or (kind == "time_provider" and base in TIME_PROVIDERS)
            if not known and sig and not sigs.is_microsoft(sig) \
                    and (sigs.lacks_trust(sig) or (kind == "network_provider" and sigs.is_valid(sig))):
                what = {"print_monitor": "Print monitor", "netsh_helper": "netsh helper", "time_provider": "Time provider",
                        "network_provider": "Network logon provider"}[kind]
                sev = "high" if sigs.lacks_trust(sig) else "medium"
                add(e, sig, "persist." + kind, f"{what} DLL that Windows did not ship: {base or cmd}", sev, "medium",
                    {"print_monitor": "Print monitors load into the spooler, which runs as SYSTEM.",
                     "netsh_helper": "Helper DLLs load whenever netsh runs.",
                     "time_provider": "Time providers load into the Windows Time service.",
                     "network_provider": "Network providers are handed every user's password at logon. Virtual "
                                         "machine and VPN products register them legitimately."}[kind],
                    [{"print_monitor": "T1547.010", "netsh_helper": "T1546.007", "time_provider": "T1547.003",
                      "network_provider": "T1556.008"}[kind]])
        elif kind == "screensaver":
            if zone != "windows" or sigs.lacks_trust(sig):
                add(e, sig, "persist.screensaver", f"Screensaver is set to a program outside Windows: {base}", "high",
                    "medium", "A screensaver is an ordinary program that Windows starts when you are idle.", ["T1546.002"])
        elif kind == "shell_open_hijack":
            add(e, sig, "persist.shell_open_hijack", f"Your account overrides how '{name}' files open", "critical", "high",
                "A per-user override of this handler either hijacks every program launch or lets a program elevate "
                "without a UAC prompt.", ["T1546.001", "T1548.002"])
        elif kind == "office_test":
            add(e, sig, "persist.office_test", "Office is set to load a DLL at startup (Office Test key)", "high", "high",
                "This key exists only for Microsoft's internal testing.", ["T1137.002"])
        elif kind == "com_hijack":
            if image and sigs.lacks_trust(sig) and zone in util.USER_WRITABLE:
                sev = "high" if meta.get("machine_wide") or zone in util.HIGH_RISK else "medium"
                add(e, sig, "persist.com_hijack", f"Per-user COM class points to an unsigned file: {base}", sev, "medium",
                    "Windows looks in your profile before the system-wide registry when it loads a component, so "
                    "a per-user entry is loaded into whichever program asks for it." +
                    (" This one overrides a system-wide class." if meta.get("machine_wide") else ""), ["T1546.015"])
        elif kind == "wmi_subscription":
            cls = meta.get("consumer_class") or ""
            if cls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
                add(e, sig, "persist.wmi.consumer", f"WMI subscription runs {'a script' if 'Script' in cls else 'a command'}: {name}",
                    "medium" if meta.get("unbound") else "high", "medium",
                    "A permanent WMI subscription runs its payload as SYSTEM whenever its trigger fires and leaves no "
                    "file in the usual autorun places. A few vendor tools use them; attackers like them more.",
                    ["T1546.003"], key_extra=(cls,))
            elif not (cls == "NTEventLogEventConsumer" and name == "SCM Event Log Consumer"):
                add(e, sig, "persist.wmi.other", f"Unusual WMI event subscription: {name} ({cls})", "low", "low",
                    "Not one of the subscriptions Windows creates.", ["T1546.003"], key_extra=(cls,))
        elif kind == "bits_job":
            if cmd:
                add(e, sig, "persist.bits.notify_command", f"Background transfer job runs a command when it finishes: {name}",
                    "high", "medium", "A transfer job with a notification command re-runs that command across "
                    "restarts until the job is cancelled.", ["T1197"])
            bad = [u for u in meta.get("urls", []) if re.match(r"^https?://\d{1,3}(?:\.\d{1,3}){3}[:/]", u or "", re.I)
                   or (re.match(r"^http://", u or "", re.I) and not _UPDATE_HOSTS.search(u))]
            if bad:
                add(e, sig, "persist.bits.odd_source", f"Background transfer job downloads from a bare IP or an unknown plain-HTTP host: {name}",
                    "medium", "low", "Browser and Windows updaters do use plain HTTP, but from their vendors' named "
                    "delivery hosts. This source is neither.", ["T1197", "T1105"],
                    extra={"flagged_urls": bad[:5]}, actions=[])
        elif kind == "ps_profile":
            for h in cl.match_text(meta.get("content", ""), "script"):
                add(e, sig, "persist.ps_profile." + h.rule.id, f"PowerShell profile {name} {h.rule.title.lower()}",
                    "high", "medium", "A profile script runs every time PowerShell starts.", ["T1546.013", *h.rule.mitre],
                    key_extra=(h.rule.id,), extra={"matched": h.match, "file": image}, actions=["quarantine"])
        elif kind == "startup_folder" and not meta.get("shortcut"):
            ext = os.path.splitext(name)[1].lower()
            if ext in (".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".ps1", ".scr", ".pif"):
                add(e, sig, "persist.startup.script", f"Script in the Startup folder: {name}", "medium", "medium",
                    "It runs at every logon. Installers put shortcuts here, not scripts.", ["T1547.001"],
                    actions=["quarantine"])

    if unquoted:
        out.append(Finding(rule="posture.service.unquoted_path", title=f"{len(unquoted)} service path(s) with spaces and no quotes",
                           severity="info", confidence="low", category="posture", collector="persistence",
                           description="Windows tries each space-separated prefix of such a path. If someone could "
                                       "write to one of those prefixes they could run code as the service. The "
                                       "default folder permissions prevent that, so this is a weakness, not a compromise.",
                           evidence={"services": unquoted[:25]}, mitre=["T1574.009"], key_parts=("unquoted",)))
    return out


def inventory(entries: list[dict]) -> dict[str, dict]:
    """Autoruns keyed for the baseline: a new key later means something added itself."""
    out = {}
    for e in entries:
        if e["kind"] in ("driver", "ps_profile", "lsa_package", "active_setup"):
            continue
        key = "|".join([e["kind"], e["location"], e["name"], (e.get("command") or "")[:300]]).lower()
        out[key] = {"kind": e["kind"], "location": e["location"], "name": e["name"],
                    "command": util.truncate(e.get("command"), 400), "image": e.get("image", "")}
    return out
