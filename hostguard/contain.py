"""Containment: stop a process, lock a file away, switch off an autorun, block an address, cut the network.

Rules every action follows
    1. Guardrails are code, not judgement. Core Windows processes, Windows' own files and
       HostGuard itself can never be targets, whoever asks.
    2. Automatic actions (actor "auto...") are narrower still: only unsigned programs and script
       hosts, only reversible actions, never anything in a folder you marked as trusted, and they
       never raise a UAC prompt. What they cannot do is queued for your approval instead.
    3. The result is read back from Windows before it is reported as done.
    4. Everything is logged with what is needed to undo it.
"""

from __future__ import annotations

import ipaddress
import os
import time

from . import paths, quarantine, reg, sigs, util, winapi
from .model import CONTAINED

NETSH = os.path.join(paths.SYSTEM32, "netsh.exe")
SCHTASKS = os.path.join(paths.SYSTEM32, "schtasks.exe")
RULE_OUT, RULE_IN = "HostGuard-Isolation-Out", "HostGuard-Isolation-In"
RATCHET_TASK = "\\HostGuard\\Isolate"

NEVER = {"system", "registry", "secure system", "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
         "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
         "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe", "securityhealthservice.exe", "sgrmbroker.exe"}
OPERATOR_ONLY = {"explorer.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe", "ctfmon.exe", "vmms.exe",
                 "vmcompute.exe", "vmwp.exe", "vmmem", "vmmemwsl", "audiodg.exe", "wslservice.exe"}
# Windows' own interpreters: signed by Microsoft, yet the right thing to stop when one runs an attack.
LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "msbuild.exe", "installutil.exe",
           "regasm.exe", "regsvcs.exe", "cmstp.exe", "wmic.exe", "schtasks.exe", "curl.exe"}
PROTECTED_SERVICES = {"windefend", "wdnissvc", "sense", "mdcoresvc", "wscsvc", "mpssvc", "bfe", "eventlog", "rpcss",
                      "dcomlaunch", "rpceptmapper", "lsm", "samss", "plugplay", "power", "profsvc", "schedule",
                      "winmgmt", "cryptsvc", "dhcp", "dnscache", "nsi", "lanmanworkstation", "gpsvc", "wuauserv",
                      "trustedinstaller", "securityhealthservice", "coremessagingregistrar", "systemeventsbroker",
                      "brokerinfrastructure", "usermanager", "termservice"}
CONTAINING = {"suspend", "kill", "quarantine", "disable_autorun", "block_ip", "isolate", "disable_user"}
UNDOABLE = {"suspend": "resume", "quarantine": "restore", "disable_autorun": "enable_autorun", "block_ip": "unblock_ip",
            "isolate": "release", "disable_user": "enable_user"}


class Refused(Exception):
    """A guardrail said no. The message is shown to the operator."""


def _auto(actor: str) -> bool:
    return actor.startswith("auto")


def _trusted() -> list[str]:
    return list((paths.load_config().get("trusted") or {}).get("paths") or [])


def _sig(path: str) -> dict | None:
    if not path:
        return None
    try:
        return sigs.check(None, [path], use_cache=False).get(util.clean_path(path).lower())
    except util.CollectError:
        return None


# ------------------------------------------------------------------ guardrails

def process_target(entity: dict, actor: str, force: bool) -> dict:
    try:
        pid = int(entity.get("pid"))
    except (TypeError, ValueError):
        raise Refused("no process id given") from None
    if pid <= 4:
        raise Refused("that is a kernel pseudo-process")
    from .scan import self_pids
    if pid in self_pids():
        raise Refused("that is HostGuard itself or the program that launched it")
    names = {p: n for p, _pp, n in winapi.list_pids()}
    if pid not in names:
        raise Refused("the process has already exited")
    live = winapi.describe_process(pid, 0, names[pid], with_token=False)
    name = names[pid].lower()
    want = entity.get("created")
    if want and live.created and abs(float(want) - live.created) > 2:
        raise Refused(f"process id {pid} now belongs to a different program ({names[pid]}); the one you meant has exited")
    if not want and entity.get("name") and str(entity["name"]).lower() != name:
        raise Refused(f"process id {pid} is {names[pid]}, not {entity['name']}")
    path = live.path or ""
    genuine = not path or util.path_zone(path) == "windows"
    if name in NEVER and genuine:
        raise Refused(f"{names[pid]} is a core Windows process; stopping it would crash or lock the PC")
    if name in OPERATOR_ONLY and genuine and (_auto(actor) or not force):
        raise Refused(f"{names[pid]} is part of the Windows desktop or the virtual machine platform; confirm with "
                      "force if you really mean it")
    sig = _sig(path)
    if _auto(actor):
        if name not in LOLBINS and not sigs.lacks_trust(sig):
            raise Refused("automatic containment only stops unsigned programs and script hosts; "
                          + (f"{names[pid]} is {sigs.describe(sig)}" if sig else f"{names[pid]} could not be inspected"))
        if path and util.is_under(path, _trusted()):
            raise Refused("it runs from a folder you marked as trusted")
    return {"type": "process", "pid": pid, "name": names[pid], "path": path, "created": live.created,
            "signature": sigs.describe(sig) if sig else None}


def file_target(entity: dict, actor: str, force: bool) -> dict:
    path = util.clean_path(str(entity.get("path") or entity.get("file") or ""))
    if not path:
        raise Refused("no file path given")
    if not os.path.isfile(path):
        raise Refused(f"{path} is not a file (it may already be gone)")
    zone = util.path_zone(path)
    if zone == "windows":
        raise Refused("the file is inside the Windows folder; removing system files breaks Windows. Use a Defender scan instead")
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    if util.is_under(path, [str(paths.OWN_DIR), str(paths.home()), os.path.join(pd, r"Microsoft\Windows Defender"),
                            os.path.join(pf, "Windows Defender")]):
        raise Refused("the file belongs to HostGuard or to Microsoft Defender")
    if os.path.dirname(path).rstrip("\\").endswith(":") and os.path.basename(path).lower() in (
            "pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr", "bootnxt"):
        raise Refused("that is a Windows system file")
    sig = _sig(path)
    if sigs.is_microsoft(sig) and not force:
        raise Refused("the file is signed by Microsoft; confirm with force if you are sure")
    if _auto(actor):
        if not sigs.checked_and_untrusted(sig):      # signed, or not known to be unsigned: unknown is not guilty
            raise Refused("automatic quarantine only takes unsigned files; this one "
                          + (f"is {sigs.describe(sig)}" if sigs.is_valid(sig) else "could not be checked"))
        if util.is_under(path, _trusted()):
            raise Refused("it is in a folder you marked as trusted")
    return {"type": "file", "path": path, "signature": sigs.describe(sig) if sig else None}


def ip_target(entity: dict, force: bool) -> dict:
    raw = str(entity.get("ip") or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        raise Refused(f"'{raw}' is not an IP address") from None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise Refused("that address is local to this PC or is not a host")
    if not ip.is_global and not force:
        raise Refused("that is a private address (your router, DNS server or another device at home); blocking it can "
                      "cut your own network. Confirm with force if you mean it")
    return {"type": "ip", "ip": str(ip)}


def autorun_target(entity: dict, actor: str, force: bool) -> dict:
    kind, name = entity.get("kind"), str(entity.get("name") or "")
    if not kind or not name:
        raise Refused("this finding does not describe an autorun entry")
    image = str(entity.get("path") or "")
    if kind in ("service", "driver"):
        if name.lower() in PROTECTED_SERVICES:
            raise Refused(f"{name} is a service Windows needs to run or to protect itself")
        if kind == "driver" and not force:
            raise Refused("disabling a driver can stop Windows from starting; confirm with force")
    if kind == "task" and name.lower().startswith("\\microsoft\\windows\\") and not force:
        raise Refused("that is one of Windows' own scheduled tasks; confirm with force")
    if kind not in ("run_key", "startup_folder", "task", "service", "driver", "logon_script", "windows_load", "cmd_autorun",
                    "ifeo_debugger", "wmi_subscription", "screensaver"):
        raise Refused(f"HostGuard cannot switch off a '{kind}' entry for you; the finding says where it is")
    if _auto(actor):
        sig = _sig(image)
        if image and os.path.isfile(image) and not sigs.checked_and_untrusted(sig) and util.basename(image) not in LOLBINS:
            raise Refused("automatic containment leaves signed programs alone; this one "
                          + (f"is {sigs.describe(sig)}" if sigs.is_valid(sig) else "could not be checked"))
        if image and util.is_under(image, _trusted()):
            raise Refused("it points into a folder you marked as trusted")
    return {"type": "autorun", "kind": kind, "location": entity.get("location") or "", "name": name,
            "command": entity.get("command") or "", "path": image, "file": entity.get("file") or ""}


# ------------------------------------------------------------------ state read-back

def _rule_exists(name: str) -> bool | None:
    rc, _out, _err = util.run_cmd([NETSH, "advfirewall", "firewall", "show", "rule", f"name={name}"], timeout=20)
    return True if rc == 0 else False if rc == 1 else None


def ratchet_installed() -> bool:
    rc, _o, _e = util.run_cmd([SCHTASKS, "/query", "/tn", RATCHET_TASK], timeout=20)
    return rc == 0


def isolation_state() -> dict:
    """Read from Windows Firewall, never from HostGuard's own records."""
    out_rule, in_rule = _rule_exists(RULE_OUT), _rule_exists(RULE_IN)
    return {"isolated": bool(out_rule) if out_rule is not None else None, "outbound_blocked": out_rule,
            "inbound_blocked": in_rule, "one_click_task": ratchet_installed()}


def _suspended(pid: int) -> bool | None:
    try:
        return winapi.is_suspended(pid)
    except (OSError, winapi.NotSupported):
        return None


# ------------------------------------------------------------------ actions

def _elevated(verb: str, args: dict, actor: str) -> dict:
    if _auto(actor):
        return {"ok": False, "needs_elevation": True,
                "message": "this needs administrator rights, and automatic actions never raise a UAC prompt"}
    from . import elevate
    return elevate.run(verb, args)


def _suspend(t: dict, actor: str) -> dict:
    try:
        winapi.suspend_process(t["pid"])
    except OSError as e:
        if "access denied" not in str(e).lower():
            return {"ok": False, "message": f"could not suspend {t['name']}: {e}"}
        res = _elevated("suspend", {"pid": t["pid"], "created": t.get("created")}, actor)
        if not res.get("ok"):
            return res
    state = _suspended(t["pid"])
    if state is False:
        return {"ok": False, "message": f"{t['name']} did not stay suspended"}
    return {"ok": True, "verified": state is True, "message": f"suspended {t['name']} (pid {t['pid']}); its memory is "
            "intact for investigation and it can be resumed", "rollback": {"kind": "resume", "pid": t["pid"],
                                                                        "created": t.get("created"), "name": t["name"]}}


def _resume(t: dict, actor: str) -> dict:
    try:
        winapi.resume_process(t["pid"])
    except OSError as e:
        if "access denied" not in str(e).lower():
            return {"ok": False, "message": f"could not resume {t['name']}: {e}"}
        res = _elevated("resume", {"pid": t["pid"], "created": t.get("created")}, actor)
        if not res.get("ok"):
            return res
    return {"ok": True, "message": f"resumed {t['name']} (pid {t['pid']})"}


def _kill(t: dict, actor: str) -> dict:
    try:
        winapi.terminate_process(t["pid"])
    except OSError as e:
        if "access denied" not in str(e).lower():
            return {"ok": False, "message": f"could not stop {t['name']}: {e}"}
        res = _elevated("kill", {"pid": t["pid"], "created": t.get("created")}, actor)
        if not res.get("ok"):
            return res
    for _ in range(20):
        if not winapi.process_alive(t["pid"]) or winapi.process_created(t["pid"]) != t.get("created"):
            return {"ok": True, "verified": True, "message": f"stopped {t['name']} (pid {t['pid']}); this cannot be undone"}
        time.sleep(0.1)
    return {"ok": False, "message": f"{t['name']} is still running"}


def _quarantine(t: dict, actor: str, finding_id: str | None, reason: str) -> dict:
    res = quarantine.put(t["path"], finding_id, reason)
    if not res.get("ok") and res.get("needs_elevation"):
        staging = str(quarantine.vault() / f"incoming-{os.getpid()}-{int(time.time())}.bin")
        er = _elevated("quarantine", {"path": t["path"], "dest": staging}, actor)
        if not er.get("ok"):
            return er
        if not os.path.isfile(staging) or os.path.exists(t["path"]):
            return {"ok": False, "message": "the elevated helper reported success but the file did not move"}
        res = quarantine.adopt(staging, t["path"], finding_id, reason)
    if res.get("ok"):
        res["verified"] = not os.path.exists(t["path"])
        res["rollback"] = {"kind": "restore", "item": res["id"]}
    return res


def _split_location(location: str):
    loc = location.replace(" (32-bit)", "")
    view = reg.V32 if location.endswith("(32-bit)") else reg.V64
    hive, _, path = loc.partition("\\")
    return hive.upper(), path, view


def _disable_autorun(t: dict, actor: str, finding_id: str | None, reason: str) -> dict:
    kind, name = t["kind"], t["name"]
    if kind == "startup_folder":
        path = t.get("file") or os.path.join(t["location"], name)
        res = _quarantine({"path": path, "name": name}, actor, finding_id, reason or "startup item disabled")
        if res.get("ok"):
            res["message"] = f"moved the startup item {name} to quarantine"
        return res
    if kind in ("run_key", "windows_load", "logon_script", "cmd_autorun", "ifeo_debugger", "screensaver"):
        hive, path, view = _split_location(t["location"])
        root = reg.HKCU if hive == "HKCU" else reg.HKLM
        value_name = "" if name == "(default)" else name
        current = reg.values(root, path, view).get(value_name)
        if current is None:
            return {"ok": False, "message": f"the value {name} is no longer there"}
        import winreg
        rollback = {"kind": "reg_value", "hive": hive, "path": path, "view": 32 if view == reg.V32 else 64,
                    "name": value_name, "value": current if isinstance(current, (str, int, list)) else reg.text(current),
                    "type": "REG_MULTI_SZ" if isinstance(current, list) else "REG_DWORD" if isinstance(current, int) else "REG_SZ"}
        if hive == "HKCU":
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE | view) as k:
                    winreg.DeleteValue(k, value_name)
            except OSError as e:
                return {"ok": False, "message": f"could not remove the value: {e}"}
        else:
            res = _elevated("reg-value-delete", {"hive": hive, "path": path, "view": rollback["view"], "name": value_name}, actor)
            if not res.get("ok"):
                return res
        gone = value_name not in reg.values(root, path, view)
        return {"ok": gone, "verified": gone, "rollback": rollback,
                "message": f"removed the autorun value {name} from {t['location']}" if gone else "the value is still there"}
    if kind == "task":
        rc, out, err = util.run_cmd([SCHTASKS, "/change", "/tn", name, "/disable"], timeout=30)
        if rc != 0:
            res = _elevated("task-disable", {"task": name}, actor)
            if not res.get("ok"):
                return res if res.get("needs_elevation") or res.get("declined") else \
                    {"ok": False, "message": f"could not disable the task: {(err or out).strip()[:200]}"}
        return {"ok": True, "message": f"disabled the scheduled task {name}", "rollback": {"kind": "task", "task": name}}
    if kind in ("service", "driver"):
        start = reg.get(reg.HKLM, rf"System\CurrentControlSet\Services\{name}", "Start")
        res = _elevated("service-disable", {"service": name}, actor)
        if not res.get("ok"):
            return res
        now = reg.get(reg.HKLM, rf"System\CurrentControlSet\Services\{name}", "Start")
        return {"ok": now == 4, "verified": now == 4, "message": f"stopped and disabled the service {name}",
                "rollback": {"kind": "service", "service": name, "start": start}}
    if kind == "wmi_subscription":
        res = _elevated("wmi-remove", {"consumer": name, "namespace": t["location"].replace("WMI ", "")}, actor)
        if res.get("ok"):
            res["message"] = f"removed the WMI subscription {name}; its definition is saved in the action log"
        return res
    return {"ok": False, "message": f"no handler for autorun kind {kind}"}


def _enable_autorun(rb: dict, actor: str) -> dict:
    kind = rb.get("kind")
    if kind == "restore":
        return quarantine.restore(rb["item"])
    if kind == "reg_value":
        if rb["hive"] == "HKCU":
            import winreg
            view = reg.V32 if rb.get("view") == 32 else reg.V64
            typ = {"REG_SZ": winreg.REG_SZ, "REG_DWORD": winreg.REG_DWORD, "REG_MULTI_SZ": winreg.REG_MULTI_SZ}[rb["type"]]
            try:
                with winreg.CreateKeyEx(reg.HKCU, rb["path"], 0, winreg.KEY_SET_VALUE | view) as k:
                    winreg.SetValueEx(k, rb["name"], 0, typ, rb["value"])
            except OSError as e:
                return {"ok": False, "message": f"could not restore the value: {e}"}
            return {"ok": True, "message": f"restored the autorun value {rb['name'] or '(default)'}"}
        return _elevated("reg-value-set", rb, actor)
    if kind == "task":
        rc, out, err = util.run_cmd([SCHTASKS, "/change", "/tn", rb["task"], "/enable"], timeout=30)
        if rc != 0:
            return _elevated("task-enable", {"task": rb["task"]}, actor)
        return {"ok": True, "message": f"re-enabled the scheduled task {rb['task']}"}
    if kind == "service":
        return _elevated("service-restore", {"service": rb["service"], "start": rb.get("start")}, actor)
    return {"ok": False, "message": "this change has no automatic undo"}


def _block_ip(t: dict, actor: str) -> dict:
    res = _elevated("block-ip", {"ip": t["ip"]}, actor)
    if not res.get("ok"):
        return res
    ok = bool(_rule_exists(f"HostGuard-Block-{t['ip']}-Out"))
    return {"ok": ok, "verified": ok, "rollback": {"kind": "unblock_ip", "ip": t["ip"]},
            "message": f"blocked all traffic to and from {t['ip']}" if ok else "the firewall rule did not appear"}


def _unblock_ip(t: dict, actor: str) -> dict:
    res = _elevated("unblock-ip", {"ip": t["ip"]}, actor)
    if not res.get("ok"):
        return res
    gone = _rule_exists(f"HostGuard-Block-{t['ip']}-Out") is False
    return {"ok": gone, "verified": gone, "message": f"unblocked {t['ip']}" if gone else "the firewall rule is still there"}


def _isolate(actor: str) -> dict:
    if isolation_state()["isolated"]:
        return {"ok": True, "verified": True, "message": "the network is already cut", "rollback": {"kind": "release"}}
    if ratchet_installed():
        rc, out, err = util.run_cmd([SCHTASKS, "/run", "/tn", RATCHET_TASK], timeout=30)
        if rc != 0:
            return {"ok": False, "message": f"the one-click isolation task did not start: {(err or out).strip()[:200]}"}
    else:
        res = _elevated("isolate", {}, actor)
        if not res.get("ok"):
            if res.get("needs_elevation"):
                res["message"] = ("cutting the network needs administrator rights. Install the one-click isolation task "
                                  "(dashboard > Hardening) so it can happen without a prompt.")
            return res
    for _ in range(40):
        if isolation_state()["isolated"]:
            return {"ok": True, "verified": True, "rollback": {"kind": "release"},
                    "message": "network isolated: every connection except this PC talking to itself is blocked"}
        time.sleep(0.25)
    return {"ok": False, "message": "the isolation rules did not appear in Windows Firewall"}


def _release(actor: str) -> dict:
    res = _elevated("release", {}, actor)
    if not res.get("ok"):
        return res
    gone = isolation_state()["isolated"] is False
    return {"ok": gone, "verified": gone, "message": "network restored" if gone else "the isolation rules are still present"}


def _user(t: dict, actor: str, enable: bool) -> dict:
    res = _elevated("user-enable" if enable else "user-disable", {"user": t["name"]}, actor)
    if res.get("ok"):
        res["message"] = f"{'enabled' if enable else 'disabled'} the account {t['name']}"
        if not enable:
            res["rollback"] = {"kind": "enable_user", "name": t["name"]}
    return res


def execute(store, action: str, entity: dict, actor: str = "operator", finding_id: str | None = None,
            dry_run: bool = False, force: bool = False, reason: str = "") -> dict:
    """Run one containment action. Returns {ok, message, ...}; never raises for an expected failure."""
    entity = dict(entity or {})
    try:
        if action in ("suspend", "resume", "kill"):
            t = process_target(entity, actor, force)
        elif action in ("quarantine", "defender_scan"):
            t = file_target(entity, actor, force)
        elif action == "disable_autorun":
            t = autorun_target(entity, actor, force)
        elif action in ("block_ip", "unblock_ip"):
            t = ip_target(entity, force)
        elif action in ("isolate", "release"):
            t = {"type": "host"}
        elif action in ("disable_user", "enable_user"):
            name = str(entity.get("name") or "").split("\\")[-1]
            if not name:
                raise Refused("no account name given")
            if name.lower() == (os.environ.get("USERNAME") or "").lower():
                raise Refused("that is the account you are logged in with")
            t = {"type": "account", "name": name}
        else:
            return {"ok": False, "message": f"unknown action '{action}'"}
        if _auto(actor) and action in ("kill",) and (paths.load_config().get("containment") or {}).get("process_action") != "kill":
            raise Refused("automatic containment suspends processes; stopping one for good is your call")
    except Refused as e:
        if store is not None and not dry_run:
            store.log_action(actor, action, entity, finding_id, state="refused", ok=False, result={"message": str(e)}, reason=reason)
        return {"ok": False, "refused": True, "message": f"refused: {e}", "target": entity}
    if dry_run:
        return {"ok": True, "dry_run": True, "target": t, "message": f"would {action.replace('_', ' ')} {_label(t)}"}
    try:
        if action == "suspend":
            res = _suspend(t, actor)
        elif action == "resume":
            res = _resume(t, actor)
        elif action == "kill":
            res = _kill(t, actor)
        elif action == "quarantine":
            res = _quarantine(t, actor, finding_id, reason)
        elif action == "defender_scan":
            from . import defender
            exe = defender.mpcmdrun()
            if not exe:
                res = {"ok": False, "message": "Defender's command-line scanner was not found"}
            else:  # a normal custom scan: Defender removes or quarantines what it recognises
                rc, text, err = util.run_cmd([exe, "-Scan", "-ScanType", "3", "-File", t["path"]], timeout=600)
                res = {"ok": rc in (0, 2), "verified": not os.path.exists(t["path"]) if rc == 2 else None,
                       "message": util.truncate((text or err).strip().replace("\r\n", " "), 300)}
        elif action == "disable_autorun":
            res = _disable_autorun(t, actor, finding_id, reason)
        elif action == "block_ip":
            res = _block_ip(t, actor)
        elif action == "unblock_ip":
            res = _unblock_ip(t, actor)
        elif action == "isolate":
            res = _isolate(actor)
        elif action == "release":
            res = _release(actor)
        else:
            res = _user(t, actor, enable=action == "enable_user")
    except Exception as e:  # an unexpected failure is still an answer, and still gets logged
        res = {"ok": False, "message": f"{type(e).__name__}: {e}"}
    ok = bool(res.get("ok"))
    rollback = res.pop("rollback", None)
    if store is not None:
        res["action_id"] = store.log_action(actor, action, t, finding_id, state="done" if ok else "failed", ok=ok,
                                            result={k: v for k, v in res.items() if k != "result"}, rollback=rollback, reason=reason)
        if ok and finding_id and action in CONTAINING:
            store.set_status(finding_id, CONTAINED)
    res["target"] = t
    res["undoable"] = ok and action in UNDOABLE
    return res


def _label(t: dict) -> str:
    return str(t.get("path") or t.get("name") or t.get("ip") or t.get("type"))


def undo(store, action_id: int, actor: str = "operator") -> dict:
    row = store.get_action(action_id)
    if not row:
        return {"ok": False, "message": f"no action {action_id}"}
    if row.get("undone"):
        return {"ok": False, "message": "that action was already undone"}
    if not row.get("ok"):
        return {"ok": False, "message": "that action did not succeed, so there is nothing to undo"}
    rb = row.get("rollback") or {}
    kind = rb.get("kind")
    if not kind:
        return {"ok": False, "message": f"'{row['action']}' cannot be undone"}
    if kind == "resume":
        res = execute(None, "resume", {"pid": rb["pid"], "created": rb.get("created"), "name": rb.get("name")}, actor, force=True)
    elif kind == "restore":
        res = quarantine.restore(rb["item"])
    elif kind in ("reg_value", "task", "service"):
        res = _enable_autorun(rb, actor)
    elif kind == "unblock_ip":
        res = _unblock_ip({"ip": rb["ip"]}, actor)
    elif kind == "release":
        res = _release(actor)
    elif kind == "enable_user":
        res = _user({"name": rb["name"]}, actor, enable=True)
    elif kind == "harden":
        from . import harden
        if rb.get("setting") in harden.ONE_WAY:
            # Older versions recorded a way back for these. There is none, and asking Windows would only
            # raise a prompt for the helper to refuse.
            return {"ok": False, "message": f"'{row['action']}' cannot be undone: that switch can be turned on from here and not off"}
        # The switch is put back the way the switch itself does it, read back from Windows and all.
        # Nothing is logged in there: the "undo" entry written below is the record of it.
        res = harden.set_state(None, str(rb.get("setting")), bool(rb.get("on")))
    else:
        return {"ok": False, "message": f"no undo for {kind}"}
    if res.get("ok"):
        store.update_action(action_id, undone=time.time(), state="undone")
        if row.get("finding_id"):
            f = store.get_finding(row["finding_id"])
            if f and f["status"] == CONTAINED:
                store.set_status(f["id"], "open")
        store.log_action(actor, "undo:" + row["action"], row["target"], row.get("finding_id"), state="done", ok=True,
                         result={"message": res.get("message"), "undoes": action_id})
    return res


def propose(store, action: str, entity: dict, finding_id: str | None, reason: str, actor: str = "policy") -> int | None:
    """Queue an action for the operator's approval. Returns the action id, or None if one is already waiting."""
    if finding_id and store.pending_for(finding_id, action):
        return None
    return store.log_action(actor, action, entity, finding_id, state="pending", ok=None, reason=reason)


def decide(store, action_id: int, approve: bool, force: bool = False) -> dict:
    row = store.get_action(action_id)
    if not row or row["state"] != "pending":
        return {"ok": False, "message": "that action is not waiting for approval"}
    if not approve:
        store.update_action(action_id, state="denied", ok=False, result={"message": "denied by the operator"})
        return {"ok": True, "message": f"denied: {row['action']} {_label(row['target'])}"}
    res = execute(store, row["action"], row["target"], actor="operator", finding_id=row.get("finding_id"), force=force,
                  reason=f"approved request {action_id}: {row.get('reason', '')}")
    store.update_action(action_id, state="approved" if res.get("ok") else "failed", ok=bool(res.get("ok")),
                        result={"message": res.get("message"), "ran_as": res.get("action_id")})
    return res
