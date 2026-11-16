"""Runs a scan: collect facts, judge them, record the result.

Profiles
    quick  the folders malware lands in, everything that auto-starts, live processes and network,
           logs for the look-back window, memory of your own processes. About a minute.
    full   as quick, plus your whole profile and ProgramData on disk and 30 days of logs.
    deep   as full, but trusts nothing cached and asks Defender about every unsigned program.

A collector that fails or lacks the rights it needs is recorded as a coverage gap. The scan never
stops because one source was unreadable, and it says plainly what it could not see.
"""

from __future__ import annotations

import os
import time
import traceback

from . import components, defender, paths, sigs, util, winapi
from .collect import eventlogs as c_events
from .collect import files as c_files
from .collect import persistence as c_persist
from .collect import system as c_system
from .detect import browsers as d_browsers
from .detect import eventlogs as d_events
from .detect import files as d_files
from .detect import memory as d_memory
from .detect import network as d_network
from .detect import persistence as d_persist
from .detect import processes as d_proc
from .detect import system as d_system
from .model import Finding, SEV_ORDER, cap_severity, verdict
from .store import Store

PROFILES = ("quick", "full", "deep")
_NEW_SEVERITY = {"autorun": "medium", "listener": "low", "account": "medium", "admin": "high", "root_cert": "medium",
                 "browser_extension": "low"}
_NEW_LABEL = {"autorun": "autorun entry", "listener": "listening port", "account": "user account",
              "admin": "administrator", "root_cert": "trusted root certificate", "browser_extension": "browser extension"}


def own_marker() -> str:
    return str(paths.OWN_DIR).lower()


def self_pids() -> set[int]:
    """This process and its ancestors (the shell or dashboard that launched the scan)."""
    if not winapi.IS_WINDOWS:
        return {os.getpid()}
    parents = {pid: ppid for pid, ppid, _ in winapi.list_pids()}
    out, pid = set(), os.getpid()
    while pid and pid not in out and len(out) < 6:
        out.add(pid)
        pid = parents.get(pid, 0)
    return out


def apply_trusted_paths(findings: list[Finding], trusted: list[str]) -> None:
    """Findings inside folders the owner declared as theirs stay visible but stop counting."""
    if not trusted:
        return
    for f in findings:
        candidates = [str((f.entity or {}).get("path") or ""), str(f.evidence.get("path") or ""),
                      str(f.evidence.get("script") or ""), str(f.evidence.get("script_file") or "")]
        if any(c and util.is_under(c, trusted) for c in candidates):
            f.severity = cap_severity(f.severity, "low")
            if "trusted-path" not in f.tags:
                f.tags.append("trusted-path")


def _second_opinions(findings: list[Finding], sig_map: dict, procs: list[dict], entries: list[dict], file_facts: dict,
                     deep: bool, log) -> list[Finding]:
    """Ask Defender's on-demand scanner about the files this scan found questionable."""
    targets: list[str] = d_files.suspects(file_facts, findings, limit=60)
    for path in [p.get("path") for p in procs] + [e.get("image") for e in entries]:
        if path and sigs.lacks_trust(sigs.lookup(sig_map, path)) and util.path_zone(path) in util.USER_WRITABLE:
            targets.append(path)
    if deep:
        targets += [f["path"] for f in file_facts.get("files") or [] if f.get("type") in ("pe", "script")]
    seen, out, asked = set(), [], 0
    for path in targets:
        key = path.lower()
        if key in seen or asked >= (400 if deep else 120):
            continue
        seen.add(key)
        res = defender.scan_file(path)
        if not res.get("ran"):
            if asked == 0 and "not found" in res.get("detail", ""):
                break
            continue
        asked += 1
        for f in findings:
            if str((f.entity or {}).get("path") or "").lower() == key:
                f.evidence["defender_second_opinion"] = res["detail"]
        for threat in res["threats"]:
            sev, label = d_system.classify_threat(threat)
            out.append(Finding(rule="file.defender.detected", title=f"Defender identifies this file as {label}: {os.path.basename(path)}",
                               severity="critical" if sev in ("high", "critical") else sev, confidence="high", category="file",
                               collector="files", description=f"Defender's on-demand scanner names it {threat}. Real-time "
                               "protection had not removed it, which happens when a file arrived while protection was off, "
                               "sits under an exclusion, or was only recently added to Defender's definitions.",
                               evidence={"path": path, "threat": threat, "sha256": util.sha256_file(path, 64 << 20)},
                               entity={"type": "file", "path": path}, mitre=["T1204.002"], actions=["quarantine", "defender_scan"],
                               key_parts=(path, threat)))
    if log:
        log(f"Defender second opinion: asked about {asked} file(s), {len(out)} flagged")
    return out


def _baseline_findings(store: Store) -> list[Finding]:
    if store.baseline_time() is None:
        return []
    out = []
    for item in store.inventory(only_new=True):
        kind, data = item["kind"], item["data"]
        label = _NEW_LABEL.get(kind, kind)
        name = data.get("name") or data.get("subject") or data.get("process") or item["key"]
        desc = ("This was not present when you accepted the baseline. New software adds entries like this; so does "
                "anything that wants to survive a restart or keep a way in.")
        ent = {}
        actions: list[str] = []
        if kind == "autorun":
            ent = {"type": "autorun", "kind": data.get("kind"), "location": data.get("location"), "name": data.get("name"),
                   "command": data.get("command"), "path": data.get("image")}
            actions = ["disable_autorun"]
        out.append(Finding(rule=f"baseline.new.{kind}", title=f"New {label} since the baseline: {util.truncate(name, 90)}",
                           severity=_NEW_SEVERITY.get(kind, "low"), confidence="low", category="persistence" if kind == "autorun" else
                           "network" if kind == "listener" else "account" if kind in ("account", "admin") else
                           "browser" if kind == "browser_extension" else "config", collector="baseline", description=desc,
                           evidence={**data, "first_seen": util.iso(item["first_seen"])}, entity=ent, actions=actions,
                           mitre=["T1547"] if kind == "autorun" else [], key_parts=(kind, item["key"])))
    return out


def run(profile: str = "quick", store: Store | None = None, cfg: dict | None = None, log=None,
        elevated_data: dict | None = None) -> dict:
    if profile not in PROFILES:
        raise ValueError(f"unknown scan profile {profile!r}; use one of {', '.join(PROFILES)}")
    store = store or Store()
    cfg = cfg or paths.load_config()
    log = log or (lambda _m: None)
    started = time.time()
    elevated = winapi.is_elevated()
    run_id = store.start_run(profile, elevated)
    deep = profile == "deep"
    days = float((cfg.get("scan") or {}).get("lookback_days", 7))
    if profile != "quick":
        days = max(days, 30.0)
    me, marker = self_pids(), own_marker()
    ctx = {"self_pids": me, "own_marker": marker}
    ed = elevated_data or {}
    gaps: list[str] = []
    ran: list[str] = []
    timings: dict[str, float] = {}
    findings: list[Finding] = []
    facts: dict = {}

    def stage(name: str, fn, default):
        t0 = time.time()
        try:
            value = fn()
            ran.append(name)
        except Exception as e:  # a broken collector must not take the scan down with it
            gaps.append(f"{name}: {e}")
            log(f"{name} failed: {e}")
            if os.environ.get("HOSTGUARD_DEBUG"):
                traceback.print_exc()
            value = default
        timings[name] = round(time.time() - t0, 1)
        return value

    # ---- collect
    log(f"scan {profile}: collecting (elevated: {'yes' if elevated else 'no'})")

    def _processes():
        procs = [p.to_dict() for p in winapi.list_processes()]
        extra = {int(p.get("pid")): p for p in ed.get("processes") or [] if p.get("pid") is not None}
        for p in procs:  # fill in what only an elevated collection could read
            e = extra.get(p["pid"])
            if e and not p.get("path"):
                p["path"], p["cmdline"], p["user"] = e.get("path"), e.get("cmdline"), e.get("user")
                p["from_elevated"] = True
        return procs

    procs = stage("processes", _processes, [])
    conns = stage("network", winapi.connections, [])
    persist = stage("persistence", lambda: c_persist.collect(log=None, include_drivers=True), {"entries": [], "gaps": []})
    gaps += persist.get("gaps") or []
    sysf = stage("system", lambda: c_system.collect(log=log), {})
    gaps += sysf.get("gaps") or []
    if ed.get("defender"):  # exclusions and detection history are only complete when read elevated
        sysf["defender"] = ed["defender"]
    for k in ("secureboot", "bitlocker"):
        if ed.get(k) is not None and isinstance(sysf.get("system"), dict):
            sysf["system"][k] = ed[k]
    events = stage("eventlogs", lambda: c_events.collect(days=days, log=log, elevated_events=ed.get("events")),
                   {"events": {}, "coverage": {}, "gaps": []})
    gaps += events.get("gaps") or []
    file_facts = stage("files", lambda: c_files.collect(profile, cfg, log=log), {"files": []})
    browsers = stage("browsers", lambda: d_browsers.collect(log=log), {"extensions": []})
    memory = stage("memory", lambda: d_memory.collect(procs, me, log=log), {"results": []})
    facts.update(processes=procs, connections=conns)
    # ---- optional add-ons, used only when you have installed them
    extra_dirs = list((cfg.get("scan") or {}).get("extra_dirs") or [])
    yara_matches = stage("yara", lambda: components.yara_scan(c_files.risky_folders(extra_dirs), log=log), []) \
        if components.find("yara") and components.yara_rules() else []
    hollows = stage("hollows_hunter", lambda: components.hollows_scan(log=log), None) if components.find("hollows_hunter") else None

    # ---- signatures
    entries = persist.get("entries") or []
    want = {p["path"] for p in procs if p.get("path")} | d_persist.paths_to_check(entries) \
        | {f["path"] for f in file_facts.get("files") or [] if f.get("type") == "pe"} | {m["path"] for m in yara_matches}
    sig_map = stage("signatures", lambda: sigs.check(store, want, use_cache=not deep, log=log), {})

    # ---- judge
    def judge(name, fn):
        try:
            got = fn()
            findings.extend(got)
        except Exception as e:
            gaps.append(f"rules for {name}: {e}")
            log(f"rules for {name} failed: {e}")
            if os.environ.get("HOSTGUARD_DEBUG"):
                traceback.print_exc()

    judge("processes", lambda: d_proc.detect({"processes": procs}, sig_map, ctx))
    judge("network", lambda: d_network.detect(facts, sig_map, ctx))
    judge("persistence", lambda: d_persist.detect(persist, sig_map, ctx))
    judge("system", lambda: d_system.detect(sysf))
    judge("eventlogs", lambda: d_events.detect(events, ctx))
    judge("files", lambda: d_files.detect(file_facts, sig_map, ctx))
    judge("browsers", lambda: d_browsers.detect(browsers, ctx))
    judge("memory", lambda: d_memory.detect(memory, sig_map, ctx))
    if yara_matches:
        judge("YARA", lambda: components.yara_findings(yara_matches, sig_map))
    if hollows:
        judge("Hollows Hunter", lambda: components.hollows_findings(hollows, procs, sig_map))
    if ed.get("hayabusa"):
        judge("Hayabusa", lambda: components.hayabusa_findings(ed["hayabusa"]))
    if (cfg.get("scan") or {}).get("defender_ondemand", True):
        t0 = time.time()
        judge("Defender second opinion", lambda: _second_opinions(findings, sig_map, procs, entries, file_facts, deep, log))
        timings["second_opinion"] = round(time.time() - t0, 1)

    # ---- baseline
    def _inventory():
        store.inventory_sync("autorun", d_persist.inventory(entries))
        store.inventory_sync("listener", d_network.inventory(facts))
        for kind, items in d_system.inventory(sysf).items():
            if items:
                store.inventory_sync(kind, items)
        store.inventory_sync("browser_extension", d_browsers.inventory(browsers))
        return _baseline_findings(store)

    if "persistence" in ran and "system" in ran:
        judge("baseline", _inventory)
        ran.append("baseline")

    apply_trusted_paths(findings, list((cfg.get("trusted") or {}).get("paths") or []))

    # ---- what this scan could not see
    blind = sum(1 for p in procs if not p.get("accessible") and p["pid"] not in (0, 4) and not p.get("from_elevated"))
    coverage = {
        "elevated": elevated or bool(ed),
        "processes_total": len(procs), "processes_without_details": blind,
        "autorun_entries": len(entries), "files_examined": file_facts.get("considered", 0),
        "files_truncated": bool(file_facts.get("truncated")),
        "memory_inspected": memory.get("inspected", 0), "event_logs": events.get("coverage") or {},
        "signatures_checked": len(sig_map), "lookback_days": days, "gaps": sorted(set(gaps)),
        "addons": {c["id"]: c["installed"] for c in components.status()},
    }
    notes = []
    if blind:
        notes.append(f"{blind} system processes could not be opened without administrator rights (their names and "
                     "parents were still checked).")
    if any(g.startswith("Security:") for g in gaps):
        notes.append("The Security log (logons, account changes, process starts) needs administrator rights. Use 'Scan with "
                     "admin rights' to include it.")
        gaps = [g for g in gaps if not g.startswith("Security:")]
        coverage["gaps"] = sorted(set(gaps))
    prefs = (sysf.get("defender") or {}).get("prefs") or {}
    if "must be an administrator" in str(prefs.get("ExclusionPath", "")).lower():
        notes.append("Defender's exclusion list is hidden from non-administrators; additions recorded in its log were checked instead.")
    if ed.get("sysmon_feature"):
        notes.append(f"Built-in Sysmon feature on this Windows build: {ed['sysmon_feature']}.")
    if ed.get("hayabusa_signer"):
        notes.append(f"Hayabusa: {ed['hayabusa_signer']}.")
    coverage["notes"] = notes

    # ---- record
    rows = [f.to_row() for f in findings]
    dedup: dict[str, dict] = {}
    for r in rows:  # two rules can describe the same thing; keep the more severe
        cur = dedup.get(r["id"])
        if cur is None or SEV_ORDER[r["severity"]] > SEV_ORDER[cur["severity"]]:
            dedup[r["id"]] = r
    state_collectors = [c for c in ran if c in ("processes", "network", "persistence", "system", "files", "browsers",
                                                "memory", "baseline")]
    change = store.upsert_findings(run_id, list(dedup.values()), state_collectors)
    open_rows = store.findings(("open",))
    v = verdict(open_rows)
    summary = {"run": run_id, "profile": profile, "started": started, "seconds": round(time.time() - started, 1),
               "verdict": v, "found_this_run": len(dedup), "new": len(change["new"]), "reopened": len(change["reopened"]),
               "coverage": coverage, "timings": timings, "baseline_set": store.baseline_time() is not None}
    store.end_run(run_id, {"ran": ran}, summary)
    log(f"scan finished in {summary['seconds']}s: {v['text']} "
        f"({v['counts']['critical']} critical, {v['counts']['high']} high, {v['counts']['medium']} medium; {len(change['new'])} new)")
    summary["new_ids"] = change["new"]
    return summary
