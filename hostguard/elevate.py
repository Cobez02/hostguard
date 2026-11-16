"""Asks Windows for administrator rights for one action (a UAC prompt), runs it, reports back.

HostGuard itself never runs elevated. The few things that need administrator rights (firewall
rules, system services, Defender settings, the Security log) go through ps/elevated.ps1, one
request per prompt. Callers confirm the outcome by reading Windows' state afterwards.
"""

from __future__ import annotations

import json
import os
import secrets
import time

from . import paths, util
from .collect import eventlogs as c_events

DECLINED = 1223


def _dir():
    return paths.sub("elevated")


def run(verb: str, args: dict | None = None, timeout: float = 300, dry_run: bool = False) -> dict:
    """{ok, message, declined, changes, data}. With dry_run nothing changes and no prompt appears."""
    token = secrets.token_hex(8)
    argfile = _dir() / f"req-{token}.json"
    resfile = _dir() / f"req-{token}.result.json"
    paths.atomic_write(argfile, json.dumps({"verb": verb, "args": args or {}, "result": str(resfile), "requested": time.time()}))
    script = "elevated.ps1" if dry_run else "elevate.ps1"
    argv = [paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
            str(paths.PS_DIR / script), "-ArgFile", str(argfile)]
    if dry_run:
        argv.append("-DryRun")
    rc, out, err = util.run_cmd(argv, timeout=timeout)
    result: dict = {}
    try:
        with open(resfile, "r", encoding="utf-8-sig") as f:
            result = json.load(f)
    except (OSError, ValueError):
        result = {}
    for f in (argfile, resfile):
        try:
            os.unlink(f)
        except OSError:
            pass
    if rc == DECLINED:
        return {"ok": False, "declined": True, "message": "administrator access was declined, so nothing was changed"}
    if rc == 124:
        return {"ok": False, "message": "timed out waiting for the administrator prompt"}
    ok = rc == 0 and bool(result.get("ok"))
    message = result.get("message") or (err or out).strip()[:300] or f"the elevated helper exited with code {rc}"
    return {"ok": ok, "declined": False, "message": message, "changes": result.get("changes") or [],
            "data": result.get("data") or {}, "dry_run": bool(result.get("dry_run"))}


def _queries(days: float = 30) -> list[dict]:
    """The same event queries a scan makes, for the logs only an administrator can read."""
    out = []
    for name, ids, cap, extra, level, min_days in c_events.QUERIES:
        if name not in ("Security", c_events.SYSMON):
            continue
        cond = "(" + " or ".join(f"EventID={i}" for i in ids) + ")"
        cond += f" and TimeCreated[timediff(@SystemTime) <= {int(max(days, min_days) * 86400 * 1000)}]"
        if level is not None:
            cond += f" and (Level={level})"
        out.append({"log": name, "xpath": f"*[System[{cond}]]" + (f" and *[{extra}]" if extra else ""), "max": cap})
    return out


def collect(days: float = 30) -> dict:
    """One UAC prompt; gathers what a normal user cannot read and leaves it for the next scan."""
    from . import components
    res = run("collect", {"outdir": str(_dir()), "queries": _queries(days), "hayabusa": components.find("hayabusa") or "",
                          "hayabusa_level": "medium"}, timeout=1800)
    if res.get("ok") and load_latest() is None:
        return {"ok": False, "message": "the elevated collection ran but left no readable result"}
    return res


def load_latest(max_age_s: float = 7200) -> dict | None:
    """The newest elevated collection as scan input, if it is recent enough to still be true."""
    path = _dir() / "latest.json"
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    when = float(data.get("when") or 0)
    if time.time() - when > max_age_s:
        return None
    events: dict[str, list] = {}
    for fname, log_name in (data.get("event_files") or {}).items():
        if os.path.basename(fname) != fname:
            continue
        try:
            with open(_dir() / fname, "r", encoding="utf-8-sig", errors="replace") as f:
                parsed = c_events.parse_events(f.read())
        except OSError:
            continue
        seen = {e["record"] for e in events.get(log_name, [])}
        events.setdefault(log_name, []).extend(e for e in parsed if e["record"] not in seen)
    defender = data.get("defender") or {}
    if isinstance(defender.get("prefs"), dict):
        defender["prefs"].setdefault("AsrExclusions", [])
    hayabusa = []
    if data.get("hayabusa_file") == "hayabusa.jsonl":
        from . import components
        try:
            with open(_dir() / "hayabusa.jsonl", "r", encoding="utf-8-sig", errors="replace") as f:
                hayabusa = components.parse_hayabusa(f.read())
        except OSError:
            hayabusa = []
    return {"when": when, "processes": util.as_list(data.get("processes")), "defender": defender,
            "secureboot": data.get("secureboot"), "bitlocker": util.as_list(data.get("bitlocker")),
            "sysmon_feature": data.get("sysmon_feature"), "events": events, "hayabusa": hayabusa,
            "hayabusa_signer": data.get("hayabusa_signer")}
