"""Everything on this PC that starts by itself: the places malware hides to survive a reboot.

Returns a flat list of entries, each {kind, location, name, command, image, args, meta}. `image`
is the program that actually runs; for a script-host entry it is the host and `args` holds the
payload.
"""

from __future__ import annotations

import os
import re

from .. import lnk, paths, reg, util

_RUN_PATHS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
]
_STARTUP_APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
_IFEO = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_SILENT_EXIT = r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
_WINLOGON = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
_WINDOWS_NT = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
_SESSION_MGR = r"System\CurrentControlSet\Control\Session Manager"
_LSA = r"System\CurrentControlSet\Control\Lsa"
_SERVICES = r"System\CurrentControlSet\Services"
_ACTIVE_SETUP = r"Software\Microsoft\Active Setup\Installed Components"
_SERVICE_TYPES = {1: "kernel driver", 2: "file system driver", 0x10: "service", 0x20: "shared service",
                  0x50: "user service", 0x60: "user service", 0x110: "interactive service"}
_START = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}


def _entry(kind: str, location: str, name: str, command: str, **meta) -> dict:
    command = reg.text(command).strip()
    image, args = util.split_command(command) if command else ("", "")
    image = util.resolve_image(image) if image else ""
    return {"kind": kind, "location": location, "name": name, "command": command, "image": image, "args": args,
            "meta": {k: v for k, v in meta.items() if v not in (None, "")}}


def _views(root):
    return [(reg.V64, ""), (reg.V32, " (32-bit)")] if root == reg.HKLM else [(reg.V64, "")]


def _disabled_startup(root, kind: str) -> set[str]:
    """Startup items switched off in Task Manager (StartupApproved: first byte odd means disabled)."""
    off = set()
    for name, data in reg.values(root, _STARTUP_APPROVED + "\\" + kind).items():
        if isinstance(data, bytes) and data and data[0] & 1:
            off.add(name.lower())
    return off


def run_keys() -> list[dict]:
    out = []
    for root in (reg.HKLM, reg.HKCU):
        rname = reg.ROOT_NAMES[root]
        off = _disabled_startup(root, "Run") | _disabled_startup(root, "Run32")
        for view, suffix in _views(root):
            for path in _RUN_PATHS:
                loc = f"{rname}\\{path}{suffix}"
                for name, data in reg.values(root, path, view).items():
                    if not name and not data:
                        continue
                    out.append(_entry("run_key", loc, name or "(default)", data,
                                      disabled=name.lower() in off, modified=reg.modified(root, path, view)))
                if path.endswith("RunOnceEx"):
                    for sub in reg.subkeys(root, path, view):
                        for name, data in reg.values(root, path + "\\" + sub, view).items():
                            out.append(_entry("run_key", f"{loc}\\{sub}", name or "(default)", data))
    return out


def startup_folders() -> list[dict]:
    out = []
    folders = [os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
               os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                            r"Microsoft\Windows\Start Menu\Programs\Startup")]
    off = _disabled_startup(reg.HKCU, "StartupFolder") | _disabled_startup(reg.HKLM, "StartupFolder")
    for folder in folders:
        try:
            items = list(os.scandir(folder))
        except OSError:
            continue
        for it in items:
            if not it.is_file() or it.name.lower() == "desktop.ini":
                continue
            meta = {"file": it.path, "disabled": it.name.lower() in off}
            try:
                meta["modified"] = it.stat().st_mtime
            except OSError:
                pass
            if it.name.lower().endswith(".lnk"):
                link = lnk.parse(it.path) or {}
                target = link.get("target") or ""
                command = (f'"{target}" {link.get("args", "")}').strip() if target else it.path
                e = _entry("startup_folder", folder, it.name, command, **meta)
                e["meta"]["shortcut"] = True
                if not target:
                    e["meta"]["unresolved_shortcut"] = True
            else:
                e = _entry("startup_folder", folder, it.name, f'"{it.path}"', **meta)
            out.append(e)
    return out


def winlogon() -> list[dict]:
    out = []
    for root in (reg.HKLM, reg.HKCU):
        rname = reg.ROOT_NAMES[root]
        vals = reg.values(root, _WINLOGON)
        for name in ("Shell", "Userinit", "Taskman", "AppSetup", "VmApplet", "GinaDLL", "System", "UIHost"):
            if name in vals and reg.text(vals[name]).strip():
                out.append(_entry("winlogon", f"{rname}\\{_WINLOGON}", name, reg.text(vals[name])))
        for sub in reg.subkeys(root, _WINLOGON + r"\Notify"):
            dll = reg.get(root, _WINLOGON + r"\Notify" + "\\" + sub, "DLLName")
            if dll:
                out.append(_entry("winlogon", f"{rname}\\{_WINLOGON}\\Notify\\{sub}", "DLLName", dll))
        nt = reg.values(root, _WINDOWS_NT)
        for name in ("Load", "Run"):
            if reg.text(nt.get(name)).strip():
                out.append(_entry("windows_load", f"{rname}\\{_WINDOWS_NT}", name, reg.text(nt[name])))
    for view, suffix in _views(reg.HKLM):
        nt = reg.values(reg.HKLM, _WINDOWS_NT, view)
        dlls = reg.text(nt.get("AppInit_DLLs")).strip()
        if dlls:
            out.append(_entry("appinit_dlls", f"HKLM\\{_WINDOWS_NT}{suffix}", "AppInit_DLLs", dlls,
                              enabled=bool(nt.get("LoadAppInit_DLLs")),
                              signed_only=bool(nt.get("RequireSignedAppInit_DLLs"))))
    return out


def ifeo() -> list[dict]:
    out = []
    for view, suffix in _views(reg.HKLM):
        for image in reg.subkeys(reg.HKLM, _IFEO, view):
            vals = reg.values(reg.HKLM, _IFEO + "\\" + image, view)
            dbg = reg.text(vals.get("Debugger")).strip()
            if dbg:
                out.append(_entry("ifeo_debugger", f"HKLM\\{_IFEO}{suffix}\\{image}", "Debugger", dbg, target_image=image))
            if isinstance(vals.get("GlobalFlag"), int) and vals["GlobalFlag"] & 0x200:
                mon = reg.text(reg.get(reg.HKLM, _SILENT_EXIT + "\\" + image, "MonitorProcess", view)).strip()
                if mon:
                    out.append(_entry("ifeo_silent_exit", f"HKLM\\{_SILENT_EXIT}{suffix}\\{image}", "MonitorProcess",
                                      mon, target_image=image))
    return out


def session_and_lsa() -> list[dict]:
    out = []
    sm = reg.values(reg.HKLM, _SESSION_MGR)
    for name in ("BootExecute", "SetupExecute", "Execute", "S0InitialCommand"):
        val = sm.get(name)
        items = val if isinstance(val, list) else [val] if val else []
        for item in items:
            if str(item).strip():
                out.append(_entry("boot_execute", f"HKLM\\{_SESSION_MGR}", name, str(item)))
    for name, data in reg.values(reg.HKLM, _SESSION_MGR + r"\AppCertDlls").items():
        out.append(_entry("appcert_dlls", f"HKLM\\{_SESSION_MGR}\\AppCertDlls", name, data))
    lsa = reg.values(reg.HKLM, _LSA)
    for name in ("Authentication Packages", "Security Packages", "Notification Packages"):
        val = lsa.get(name)
        for item in (val if isinstance(val, list) else [val] if val else []):
            item = str(item).strip().strip('"')
            if item:
                out.append({"kind": "lsa_package", "location": f"HKLM\\{_LSA}", "name": name, "command": item,
                            "image": util.resolve_image(item if item.lower().endswith(".dll") else item + ".dll"),
                            "args": "", "meta": {}})
    for item in (reg.get(reg.HKLM, _LSA + r"\OSConfig", "Security Packages") or []):
        item = str(item).strip().strip('"')
        if item:
            out.append({"kind": "lsa_package", "location": f"HKLM\\{_LSA}\\OSConfig", "name": "Security Packages",
                        "command": item, "image": util.resolve_image(item if item.lower().endswith(".dll") else item + ".dll"),
                        "args": "", "meta": {}})
    mon = r"System\CurrentControlSet\Control\Print\Monitors"
    for sub in reg.subkeys(reg.HKLM, mon):
        dll = reg.get(reg.HKLM, mon + "\\" + sub, "Driver")
        if dll:
            out.append(_entry("print_monitor", f"HKLM\\{mon}\\{sub}", "Driver", dll))
    for name, data in reg.values(reg.HKLM, r"Software\Microsoft\NetSh").items():
        out.append(_entry("netsh_helper", r"HKLM\Software\Microsoft\NetSh", name, data))
    tp = r"System\CurrentControlSet\Services\W32Time\TimeProviders"
    for sub in reg.subkeys(reg.HKLM, tp):
        dll = reg.get(reg.HKLM, tp + "\\" + sub, "DllName")
        if dll:
            out.append(_entry("time_provider", f"HKLM\\{tp}\\{sub}", "DllName", dll))
    order = reg.text(reg.get(reg.HKLM, r"System\CurrentControlSet\Control\NetworkProvider\Order", "ProviderOrder"))
    for prov in [p.strip() for p in order.split(",") if p.strip()]:
        dll = reg.get(reg.HKLM, f"{_SERVICES}\\{prov}\\NetworkProvider", "ProviderPath")
        if dll:
            out.append(_entry("network_provider", f"HKLM\\{_SERVICES}\\{prov}\\NetworkProvider", prov, dll))
    return out


def active_setup() -> list[dict]:
    out = []
    for view, suffix in _views(reg.HKLM):
        for sub in reg.subkeys(reg.HKLM, _ACTIVE_SETUP, view):
            vals = reg.values(reg.HKLM, _ACTIVE_SETUP + "\\" + sub, view)
            stub = reg.text(vals.get("StubPath")).strip()
            if stub:
                out.append(_entry("active_setup", f"HKLM\\{_ACTIVE_SETUP}{suffix}\\{sub}", reg.text(vals.get("")) or sub, stub))
    return out


def user_hooks() -> list[dict]:
    """Per-user spots that need no administrator rights, so they are the first choice of most malware."""
    out = []
    script = reg.text(reg.get(reg.HKCU, "Environment", "UserInitMprLogonScript")).strip()
    if script:
        out.append(_entry("logon_script", r"HKCU\Environment", "UserInitMprLogonScript", script))
    scr = reg.text(reg.get(reg.HKCU, r"Control Panel\Desktop", "SCRNSAVE.EXE")).strip()
    if scr:
        out.append(_entry("screensaver", r"HKCU\Control Panel\Desktop", "SCRNSAVE.EXE", scr))
    for root in (reg.HKCU, reg.HKLM):
        auto = reg.text(reg.get(root, r"Software\Microsoft\Command Processor", "AutoRun")).strip()
        if auto:
            out.append(_entry("cmd_autorun", f"{reg.ROOT_NAMES[root]}\\Software\\Microsoft\\Command Processor", "AutoRun", auto))
    for cls in ("exefile", "ms-settings", "mscfile", "Folder", ".exe", "batfile", "cmdfile", "comfile"):
        key = rf"Software\Classes\{cls}\shell\open\command"
        vals = reg.values(reg.HKCU, key)
        if vals:
            out.append(_entry("shell_open_hijack", "HKCU\\" + key, cls,
                              reg.text(vals.get("")) or "(DelegateExecute cleared)",
                              delegate=reg.text(vals.get("DelegateExecute")) if "DelegateExecute" in vals else None))
    perf = reg.text(reg.get(reg.HKCU, r"Software\Microsoft\Office test\Special\Perf", "")).strip()
    if perf:
        out.append(_entry("office_test", r"HKCU\Software\Microsoft\Office test\Special\Perf", "(default)", perf))
    clsid = r"Software\Classes\CLSID"
    for sub in reg.subkeys(reg.HKCU, clsid):
        for server in ("InprocServer32", "LocalServer32"):
            val = reg.text(reg.get(reg.HKCU, f"{clsid}\\{sub}\\{server}", "")).strip()
            if val:
                out.append(_entry("com_hijack", f"HKCU\\{clsid}\\{sub}\\{server}", sub, val,
                                  machine_wide=reg.exists(reg.HKLM, f"{clsid}\\{sub}")))
    return out


def services(include_drivers: bool = True) -> list[dict]:
    out = []
    for name in reg.subkeys(reg.HKLM, _SERVICES):
        key = _SERVICES + "\\" + name
        vals = reg.values(reg.HKLM, key)
        typ = vals.get("Type")
        if not isinstance(typ, int):
            continue
        is_driver = typ in (1, 2, 8)
        if is_driver and not include_drivers:
            continue
        image_path = reg.text(vals.get("ImagePath")).strip()
        dll = reg.text(reg.get(reg.HKLM, key + r"\Parameters", "ServiceDll") or vals.get("ServiceDll")).strip()
        if not image_path and not dll:
            continue
        if is_driver and not image_path:
            continue
        e = _entry("driver" if is_driver else "service", f"HKLM\\{key}", name, image_path,
                   display=reg.text(vals.get("DisplayName")), start=_START.get(vals.get("Start"), str(vals.get("Start"))),
                   type=_SERVICE_TYPES.get(typ & 0x1FF, hex(typ)), account=reg.text(vals.get("ObjectName")),
                   failure_command=reg.text(vals.get("FailureCommand")), modified=reg.modified(reg.HKLM, key),
                   raw_image_path=image_path)
        if is_driver and e["image"] and not os.path.isabs(e["image"]):
            e["image"] = os.path.join(paths.WINDIR, e["image"])
        if dll:
            e["meta"]["service_dll"] = util.clean_path(dll)
        out.append(e)
    return out


def tasks() -> list[dict]:
    out = []
    for t in util.as_list(util.run_ps("tasks", timeout=120)):
        full = (t.get("path") or "\\") + (t.get("name") or "")
        meta = {"author": t.get("author"), "state": t.get("state"), "user": t.get("user") or t.get("group"),
                "runlevel": t.get("runlevel"), "hidden": bool(t.get("hidden")), "created": t.get("date"),
                "triggers": ", ".join(util.as_list(t.get("triggers"))), "description": util.truncate(t.get("description"), 200),
                "disabled": t.get("state") == "Disabled"}
        actions = util.as_list(t.get("actions"))
        if not actions:
            continue
        for a in actions:
            if a.get("type") == "exec":
                exe = (a.get("execute") or "").strip()
                arg = (a.get("arguments") or "").strip()
                command = (f'"{exe}" {arg}' if " " in exe and not exe.startswith('"') else f"{exe} {arg}").strip()
                out.append(_entry("task", "Task Scheduler", full, command, **meta))
            elif a.get("type") == "com":
                clsid = (a.get("classid") or "").strip()
                server = ""
                for root in (reg.HKCU, reg.HKLM):
                    for srv in ("InprocServer32", "LocalServer32"):
                        server = server or reg.text(reg.get(root, rf"Software\Classes\CLSID\{clsid}\{srv}", "")).strip()
                e = _entry("task", "Task Scheduler", full, server, com_handler=clsid, **meta)
                e["meta"]["user_override"] = reg.exists(reg.HKCU, rf"Software\Classes\CLSID\{clsid}")
                out.append(e)
    return out


def wmi_subscriptions() -> tuple[list[dict], list[str]]:
    data = util.run_ps("wmi", timeout=60) or {}
    consumers = {(c.get("ns"), c.get("name")): c for c in util.as_list(data.get("consumers"))}
    filters = {(f.get("ns"), f.get("name")): f for f in util.as_list(data.get("filters"))}
    out = []
    bound = set()
    for b in util.as_list(data.get("bindings")):
        c = consumers.get((b.get("ns"), b.get("consumer")), {})
        f = filters.get((b.get("ns"), b.get("filter")), {})
        bound.add((b.get("ns"), b.get("consumer")))
        command = c.get("command") or c.get("exe") or c.get("scriptfile") or util.truncate(c.get("script"), 2000) or ""
        e = _entry("wmi_subscription", f"WMI {b.get('ns')}", b.get("consumer") or "", command,
                   consumer_class=c.get("class") or b.get("consumer_class"), filter=b.get("filter"),
                   query=f.get("query"), script_engine=c.get("engine"))
        e["meta"]["has_script"] = bool(c.get("script"))
        out.append(e)
    for key, c in consumers.items():  # a consumer with no binding does nothing yet, but someone made it
        if key not in bound and c.get("class") in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            command = c.get("command") or c.get("exe") or c.get("scriptfile") or util.truncate(c.get("script"), 2000) or ""
            e = _entry("wmi_subscription", f"WMI {c.get('ns')}", c.get("name") or "", command,
                       consumer_class=c.get("class"), unbound=True)
            out.append(e)
    return out, [str(x) for x in util.as_list(data.get("errors"))]


def bits_jobs() -> list[dict]:
    data = util.run_ps("bits", timeout=90) or {}
    notify = {}
    block_id = None
    for line in (data.get("verbose") or "").splitlines():
        m = re.match(r"^GUID:\s*\{([0-9A-Fa-f-]+)\}", line.strip())
        if m:
            block_id = m.group(1).lower()
        m = re.match(r"^NOTIFICATION COMMAND LINE:\s*(.*)$", line.strip())
        if m and block_id:
            notify[block_id] = m.group(1).strip()
    out = []
    for jb in util.as_list(data.get("jobs")):
        files = util.as_list(jb.get("files"))
        cmd = notify.get(str(jb.get("id") or "").lower(), "")
        if cmd.lower() in ("none", ""):
            cmd = ""
        owner = jb.get("owner")
        if isinstance(owner, dict):
            owner = owner.get("Value")
        e = _entry("bits_job", "BITS", jb.get("name") or str(jb.get("id")), cmd, state=jb.get("state"),
                   owner=owner, created=jb.get("created"),
                   urls=[f.get("remote") for f in files if f.get("remote")][:10],
                   local=[f.get("local") for f in files if f.get("local")][:10])
        out.append(e)
    return out


def powershell_profiles() -> list[dict]:
    out = []
    docs = [os.path.join(os.environ.get("USERPROFILE", ""), "Documents"),
            os.path.join(os.environ.get("USERPROFILE", ""), "OneDrive", "Documents")]
    candidates = [os.path.join(paths.SYSTEM32, r"WindowsPowerShell\v1.0\profile.ps1"),
                  os.path.join(paths.SYSTEM32, r"WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"),
                  os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), r"PowerShell\7\profile.ps1")]
    for d in docs:
        for sub in ("WindowsPowerShell", "PowerShell"):
            for fn in ("profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.VSCode_profile.ps1"):
                candidates.append(os.path.join(d, sub, fn))
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                text = f.read(200000)
            mtime = os.stat(path).st_mtime
        except OSError:
            continue
        out.append({"kind": "ps_profile", "location": os.path.dirname(path), "name": os.path.basename(path),
                    "command": f'"{path}"', "image": path, "args": "", "meta": {"content": text, "modified": mtime}})
    return out


def collect(log=None, include_drivers: bool = True) -> dict:
    """All autorun entries plus the names of the sources that could not be read."""
    entries: list[dict] = []
    gaps: list[str] = []
    for name, fn in (("run keys", run_keys), ("startup folders", startup_folders), ("winlogon", winlogon),
                     ("image file execution options", ifeo), ("session manager and LSA", session_and_lsa),
                     ("active setup", active_setup), ("user hooks", user_hooks),
                     ("services", lambda: services(include_drivers)), ("scheduled tasks", tasks),
                     ("BITS jobs", bits_jobs), ("PowerShell profiles", powershell_profiles)):
        try:
            got = fn()
            entries += got
            if log:
                log(f"{name}: {len(got)}")
        except (util.CollectError, OSError) as e:
            gaps.append(f"{name}: {e}")
    try:
        subs, errors = wmi_subscriptions()
        entries += subs
        gaps += [f"WMI subscriptions: {e}" for e in errors]
    except (util.CollectError, OSError) as e:
        gaps.append(f"WMI subscriptions: {e}")
    return {"entries": entries, "gaps": gaps}
