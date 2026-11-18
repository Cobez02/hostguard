"""Rules over running processes: impostors, abused Windows tools, odd parents, unsigned code."""

from __future__ import annotations

import os
import re
import unicodedata

from .. import paths, sigs, util
from ..model import Finding, bump
from . import cmdline as cl

_WIN = paths.WINDIR.lower()
_S32 = _WIN + "\\system32"
_W64 = _WIN + "\\syswow64"

# Core Windows processes and the only folders their image may run from.
SYSTEM_IMAGES: dict[str, tuple[str, ...]] = {
    "svchost.exe": (_S32, _W64), "lsass.exe": (_S32,), "csrss.exe": (_S32,), "smss.exe": (_S32,),
    "services.exe": (_S32,), "winlogon.exe": (_S32,), "wininit.exe": (_S32,), "lsaiso.exe": (_S32,),
    "explorer.exe": (_WIN, _W64), "taskhostw.exe": (_S32,), "dllhost.exe": (_S32, _W64),
    "conhost.exe": (_S32,), "rundll32.exe": (_S32, _W64), "regsvr32.exe": (_S32, _W64),
    "spoolsv.exe": (_S32,), "dwm.exe": (_S32,), "fontdrvhost.exe": (_S32,), "sihost.exe": (_S32,),
    "ctfmon.exe": (_S32,), "runtimebroker.exe": (_S32,), "searchindexer.exe": (_S32,),
    "userinit.exe": (_S32,), "logonui.exe": (_S32,), "wmiprvse.exe": (_S32 + "\\wbem", _W64 + "\\wbem"),
    "wudfhost.exe": (_S32,), "audiodg.exe": (_S32,), "cmd.exe": (_S32, _W64),
    "powershell.exe": (_S32 + "\\windowspowershell\\v1.0", _W64 + "\\windowspowershell\\v1.0"),
    "mshta.exe": (_S32, _W64), "wscript.exe": (_S32, _W64), "cscript.exe": (_S32, _W64),
    "msiexec.exe": (_S32, _W64), "certutil.exe": (_S32, _W64), "werfault.exe": (_S32, _W64),
    "taskeng.exe": (_S32,), "securityhealthservice.exe": (_S32,), "sppsvc.exe": (_S32,),
    "searchprotocolhost.exe": (_S32, _W64), "searchfilterhost.exe": (_S32, _W64), "wermgr.exe": (_S32, _W64),
}
# Names worth guarding against look-alikes (svch0st.exe, lsasss.exe).
_LOOKALIKE_TARGETS = ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "explorer.exe",
                      "spoolsv.exe", "taskhostw.exe", "rundll32.exe", "dllhost.exe", "conhost.exe", "smss.exe",
                      "wininit.exe", "chrome.exe", "msedge.exe", "firefox.exe", "runtimebroker.exe")
_REAL_NEIGHBOURS = {"sihost.exe", "lsaiso.exe", "taskhost.exe", "svchost.exe", "dashost.exe", "smss.exe",
                    "csrss.exe", "msedge.exe", "chrome.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
                    "iexplore.exe", "service.exe", "chromes.exe"}

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
          "visio.exe", "eqnedt32.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "foxitreader.exe",
          "wordpad.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe", "wmic.exe",
          "installutil.exe", "msbuild.exe", "curl.exe", "bash.exe", "wsl.exe"}
UAC_EXEMPT = {"fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe", "wsreset.exe", "slui.exe",
              "cmstp.exe"}
RISKY_EXT = {".scr", ".pif", ".com", ".cpl"}
_DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4",
            "zip", "rar", "csv", "rtf", "html", "htm"}


def _ascii_skeleton(name: str) -> str:
    return unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()


def _proc_entity(p: dict) -> dict:
    return {"type": "process", "pid": p["pid"], "name": p["name"], "path": p.get("path") or "",
            "created": p.get("created")}


def _proc_evidence(p: dict, parent: dict | None, sig: dict | None) -> dict:
    ev = {"pid": p["pid"], "name": p["name"], "path": p.get("path"), "command_line": util.truncate(p.get("cmdline"), 1200),
          "user": p.get("user"), "integrity": p.get("integrity"), "started": util.iso(p.get("created")),
          "signature": sigs.describe(sig)}
    if parent:
        ev["parent"] = f"{parent['name']} (pid {parent['pid']})"
        if parent.get("path"):
            ev["parent_path"] = parent["path"]
    return {k: v for k, v in ev.items() if v not in (None, "")}


_ARG = re.compile(r'(?:[^\s"]+|"[^"]*")+')


def browser_switches(cmdline: str, any_prefix: bool = False) -> dict[str, str]:
    """The switches on a browser's command line, read the way a Chromium browser reads them.

    A switch is an argument that starts with two dashes; its name is not case-sensitive; and a
    bare -- ends the switches, so everything after it is an address to open. Looking for a
    switch's name anywhere in the line instead would let an address that merely contains the
    name pass for the switch.

    On Windows these browsers also take a switch written with one dash or with a slash (checked
    against Edge: the debugging port opens either way). any_prefix reads those spellings too. It
    is for the switch whose presence is the warning sign, so that no spelling slips past. A
    switch that excuses a process is only taken the way the browser itself writes it.
    """
    out: dict[str, str] = {}
    prefixes = ("--", "-", "/") if any_prefix else ("--",)
    for arg in (a.replace('"', "") for a in _ARG.findall(cmdline or "")[1:]):
        if arg == "--":
            break
        prefix = next((x for x in prefixes if arg.startswith(x) and len(arg) > len(x)), None)
        if prefix:
            name, _, value = arg[len(prefix):].partition("=")
            out[name.lower()] = value
    return out


def double_extension(name: str) -> bool:
    parts = name.lower().split(".")
    return len(parts) >= 3 and parts[-1] in ("exe", "scr", "com", "pif", "bat", "cmd", "js", "vbs", "lnk") \
        and parts[-2] in _DOC_EXT


def detect(facts: dict, sig_map: dict[str, dict], ctx: dict | None = None) -> list[Finding]:
    """facts["processes"]: list of Proc dicts. sig_map: lower-cased path -> signature verdict."""
    ctx = ctx or {}
    procs = facts.get("processes") or []
    by_pid = {p["pid"]: p for p in procs}
    self_pids = set(ctx.get("self_pids") or ())
    out: list[Finding] = []

    def parent_of(p: dict) -> dict | None:
        par = by_pid.get(p.get("ppid"))
        if not par or par["pid"] == p["pid"]:
            return None
        if par.get("created") and p.get("created") and par["created"] > p["created"] + 1:
            return None  # the parent PID was reused by a younger process
        return par

    def add(p, par, sig, rule, title, sev, conf, desc, mitre, key_extra=(), actions=("suspend", "kill"),
            extra=None, remediation="", tags=()):
        ev = _proc_evidence(p, par, sig)
        if extra:
            ev.update(extra)
        acts = list(actions)
        if p.get("path") and "quarantine" not in acts and util.path_zone(p["path"]) in util.USER_WRITABLE:
            acts.append("quarantine")
        out.append(Finding(rule=rule, title=title, severity=sev, confidence=conf, category="process",
                           description=desc, evidence=ev, entity=_proc_entity(p), mitre=list(mitre),
                           actions=acts, collector="processes", remediation=remediation, tags=list(tags),
                           key_parts=((p.get("path") or p["name"]), *key_extra)))

    for p in procs:
        if p["pid"] in (0, 4) or p["pid"] in self_pids:
            continue
        name = (p.get("name") or "").lower()
        path = p.get("path") or ""
        low = path.lower()
        folder = os.path.dirname(low)
        zone = util.path_zone(path) if path else None
        sig = sigs.lookup(sig_map, path)
        par = parent_of(p)
        pname = (par["name"].lower() if par else "")
        cmd = p.get("cmdline") or ""

        # ---- impostors
        if name in SYSTEM_IMAGES and path:
            allowed = SYSTEM_IMAGES[name]
            ok = folder in allowed or low.startswith(_WIN + "\\winsxs\\") or low.startswith(_WIN + "\\systemtemp\\")
            if not ok:
                sev = "critical" if zone in util.USER_WRITABLE else "high"
                if sigs.is_microsoft(sig):
                    sev = "medium"  # a genuine Microsoft binary copied elsewhere: odd, sometimes a LOLBin trick
                add(p, par, sig, "proc.masquerade.system_name",
                    f"{p['name']} is running from the wrong folder", sev, "high",
                    f"A process named like the Windows component {p['name']} runs from {folder}, not from "
                    f"{allowed[0]}. Malware takes these names to blend into the process list.",
                    ("T1036.005",))
        elif name and name not in SYSTEM_IMAGES and name not in _REAL_NEIGHBOURS:
            skeleton = _ascii_skeleton(name)
            for target in _LOOKALIKE_TARGETS:
                if name == target:
                    break
                if skeleton == target and name != target:
                    add(p, par, sig, "proc.masquerade.homoglyph", f"{p['name']} imitates {target} with look-alike letters",
                        "high", "high", "The name uses non-Latin characters that render like a Windows process name.",
                        ("T1036.005",))
                    break
                if abs(len(name) - len(target)) <= 1 and util.levenshtein(name, target, 1) == 1 \
                        and not sigs.is_valid(sig):
                    add(p, par, sig, "proc.masquerade.lookalike", f"{p['name']} looks like {target}", "high", "medium",
                        f"The name is one character away from the Windows process {target} and the file is "
                        f"{sigs.describe(sig)}.", ("T1036.005",))
                    break

        if double_extension(name):
            add(p, par, sig, "proc.name.double_extension", f"{p['name']} hides its real type behind a document extension",
                "high", "high", "A program named like a document (file.pdf.exe) exists to be opened by mistake.",
                ("T1036.007",))
        elif os.path.splitext(name)[1] in RISKY_EXT and zone in util.USER_WRITABLE:
            add(p, par, sig, "proc.name.risky_extension", f"{p['name']} runs with an unusual executable extension",
                "medium", "medium", "Programs with .scr, .pif, .com or .cpl extensions in user folders are rare "
                "outside malware delivery.", ("T1036",))

        # ---- signature and location
        if path and sigs.is_tampered(sig):
            add(p, par, sig, "proc.signature.tampered", f"{p['name']} was modified after it was signed", "high", "high",
                "The file carries a publisher signature that no longer matches its contents. Either it was "
                "patched or it is corrupt.", ("T1554",))
        if path and sig and sig["status"] == "Missing":
            add(p, par, sig, "proc.image.deleted", f"{p['name']} is running but its file is gone", "medium", "medium",
                "The program deleted itself or was removed after it started. Droppers do this to leave nothing "
                "to scan. Updaters occasionally do it too.", ("T1070.004",), actions=("suspend", "kill"))
        if path and sigs.lacks_trust(sig) and zone in util.USER_WRITABLE:
            sev = "medium" if zone in util.HIGH_RISK else "low"
            where = {"temp": "the Temp folder", "downloads": "Downloads", "public": "the Public profile",
                     "recycle": "the Recycle Bin", "appdata": "AppData", "programdata": "ProgramData",
                     "desktop": "the Desktop"}.get(zone, "a user-writable folder")
            add(p, par, sig, "proc.unsigned.user_writable", f"Unsigned program running from {where}: {p['name']}",
                sev, "low",
                "No publisher signed this file and it runs from a folder that any program can write to. "
                "Plenty of developer tools look like this, and so does most commodity malware.",
                ("T1204.002",), tags=("unsigned",))
        if low and ("\\$recycle.bin\\" in low or low.startswith((_WIN + "\\fonts\\", _WIN + "\\debug\\", _WIN + "\\tasks\\"))
                    or "\\system volume information\\" in low):
            add(p, par, sig, "proc.path.hiding_place", f"{p['name']} runs from a folder programs never live in",
                "high", "high", f"The image is at {path}.", ("T1564", "T1036.005"))

        # ---- command-line rules
        hits = cl.analyse_command(cmd) if cmd else []
        flags = cl.powershell_flags(cmd) if cmd else {}
        for h in hits:
            sev, conf = h.rule.severity, h.rule.confidence
            tags = []
            if pname == "explorer.exe" and h.rule.id in ("cmd.download_cradle", "cmd.mshta_remote", "cmd.curl_pipe_shell"):
                tags.append("clickfix-style")
                sev, conf = bump(sev), "high"
            extra = {"matched": h.match, "urls": cl.urls_in(cmd + " " + (flags.get("decoded") or ""))}
            if h.decoded:
                extra["decoded_command"] = util.truncate(flags.get("decoded"), 1500)
            vendor = cl.known_installer(cmd) if h.rule.id == "cmd.download_cradle" and "clickfix-style" not in tags else None
            if vendor:
                sev, conf = "low", "low"
                tags.append("known-installer")
                extra["known_installer"] = vendor
            add(p, par, sig, "proc." + h.rule.id, f"{h.rule.title}: {p['name']}", sev, conf,
                h.rule.why or h.rule.title + ".", h.rule.mitre, key_extra=(h.match[:80],), extra=extra, tags=tags)
        if flags.get("is_powershell") and not hits:
            decoded = flags.get("decoded")
            if decoded and flags.get("hidden"):
                add(p, par, sig, "proc.ps.hidden_encoded", "Hidden PowerShell runs an encoded command", "medium", "medium",
                    "The window is hidden and the script is base64-encoded. The decoded script is attached; "
                    "nothing in it matched an attack pattern.", ("T1059.001", "T1027"),
                    key_extra=(decoded[:80],), extra={"decoded_command": util.truncate(decoded, 1500)})
            elif decoded:
                add(p, par, sig, "proc.ps.encoded", "PowerShell runs an encoded command", "low", "low",
                    "The script is base64-encoded, which some installers and management tools do. The decoded "
                    "script is attached.", ("T1027",), key_extra=(decoded[:80],),
                    extra={"decoded_command": util.truncate(decoded, 1500)})

        # ---- parents and children
        if par:
            if pname in OFFICE and name in SHELLS:
                add(p, par, sig, "proc.parent.office_shell", f"{par['name']} started {p['name']}", "high", "high",
                    "A document viewer launching a shell or script host is how macro and exploit documents run "
                    "their payload.", ("T1204.002", "T1566.001"), key_extra=(pname,))
            elif pname in BROWSERS and name in ({"powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe",
                                                 "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}):
                add(p, par, sig, "proc.parent.browser_shell", f"{par['name']} started {p['name']}", "high", "medium",
                    "Browsers have no reason to start a script host. This points at an exploit or a malicious "
                    "extension's native helper.", ("T1189", "T1059"), key_extra=(pname,))
            elif pname in SCRIPT_HOSTS and name in {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
                                                    "certutil.exe", "bitsadmin.exe", "mshta.exe"}:
                add(p, par, sig, "proc.parent.script_chain", f"{par['name']} started {p['name']}", "medium", "medium",
                    "A script host launching another interpreter is a staged-loader pattern.", ("T1059",),
                    key_extra=(pname,))
            elif pname == "winlogon.exe" and name in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
                add(p, par, sig, "proc.parent.winlogon_shell", f"The logon screen started {p['name']}", "critical", "high",
                    "A shell spawned by winlogon.exe is the signature of an accessibility-tool backdoor "
                    "(Sticky Keys): a SYSTEM prompt on the lock screen.", ("T1546.008",))
            elif pname == "lsass.exe" and name not in {"werfault.exe", "lsaiso.exe", "efsui.exe"}:
                add(p, par, sig, "proc.parent.lsass_child", f"The credential store process started {p['name']}", "high",
                    "medium", "lsass.exe does not normally start programs.", ("T1055",))
            elif pname == "wmiprvse.exe" and name in {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe"}:
                add(p, par, sig, "proc.parent.wmi_exec", f"WMI started {p['name']}", "medium", "low",
                    "Commands launched through WMI are used for remote execution and by WMI persistence. "
                    "Some management software does this legitimately.", ("T1047",))
            elif pname == "services.exe" and name in {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe"}:
                add(p, par, sig, "proc.parent.service_shell", f"The service manager started {p['name']}", "high", "medium",
                    "A service whose program is a shell is how PsExec-style remote execution and privilege "
                    "escalation tools run commands as SYSTEM.", ("T1569.002", "T1543.003"))
            elif pname in UAC_EXEMPT and name in SHELLS | {"python.exe", "pythonw.exe"}:
                add(p, par, sig, "proc.parent.uac_bypass", f"{par['name']} started {p['name']}", "high", "medium",
                    f"{par['name']} elevates without a prompt, and programs abuse it to run their own code "
                    "elevated.", ("T1548.002",), key_extra=(pname,))

        # ---- remote access and browser automation
        product = cl.remote_tool(name)
        if product:
            sev = "medium"
            desc = (f"{product} gives someone else control of or a route into this PC. That is fine if you "
                    "installed it and know who can connect. Intruders and support scammers install the same tools.")
            if product == "NetSupport Manager" and zone in util.USER_WRITABLE:
                sev, desc = "critical", ("NetSupport Manager running from a user folder is a common malware payload "
                                         "(NetSupport RAT): the legitimate product installs under Program Files.")
            elif product in ("Tailscale", "OpenSSH server", "Parsec", "Windows Quick Assist / Remote Assistance",
                             "ZeroTier") and zone not in util.USER_WRITABLE:
                sev = "low"
            add(p, par, sig, "proc.remote_access_tool", f"Remote access software is running: {product}", sev, "low",
                desc, ("T1219",), key_extra=(product,), actions=("suspend", "kill"),
                remediation="Confirm you installed it and check who is allowed to connect. Uninstall it otherwise.")
        if name in BROWSERS and cmd and "remote-debugging-port" in browser_switches(cmd, any_prefix=True):
            switches = browser_switches(cmd)
            # Only the browser itself opens the port. Its renderer, GPU and utility processes are handed
            # the same switch and open nothing, so they are not what to report or to stop. A headless
            # browser is test automation; its helpers do not carry --headless, only their --type.
            if "headless" not in switches and not switches.get("type"):
                add(p, par, sig, "proc.browser.remote_debugging", f"{p['name']} is running with remote debugging open",
                    "medium", "low",
                    "Anything on this PC can drive a browser started this way and read its cookies and saved "
                    "sessions. Test automation does it on purpose; so do infostealers.", ("T1185", "T1539"),
                    actions=("kill",))
    return out
