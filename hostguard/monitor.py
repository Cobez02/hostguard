"""The real-time monitor: a small loop that notices new processes, connections, autoruns, files and
log events as they happen, judges them with the same rules as a scan, and hands what it finds to
the containment policy.

It runs as you, without administrator rights. That covers programs running in your session, which
is where nearly all home-PC malware lives. A process that starts and exits between two polls can
be missed; switching on command-line auditing or Sysmon (dashboard > Hardening) closes that
gap, because the monitor also reads the logs those features write.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from . import defender, notify, paths, policy, reg, sigs, util, winapi
from .collect import eventlogs as c_events
from .collect import files as c_files
from .collect import persistence as c_persist
from .collect import system as c_system
from .detect import eventlogs as d_events
from .detect import files as d_files
from .detect import network as d_network
from .detect import persistence as d_persist
from .detect import processes as d_proc
from .detect import system as d_system
from .model import Finding, SEV_ORDER
from .store import Store

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "HostGuard"
_DETACHED = 0x00000008 | 0x00000200 | getattr(subprocess, "CREATE_NO_WINDOW", 0)


def state_path():
    return paths.home() / "monitor.json"


def stop_path():
    return paths.home() / "monitor.stop"


def _read_state() -> dict:
    try:
        return json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def status() -> dict:
    """Whether the monitor is really running: its recorded PID must be alive, be the same process
    that wrote the record, and have written a heartbeat recently."""
    st = _read_state()
    pid = int(st.get("pid") or 0)
    alive = bool(pid) and winapi.IS_WINDOWS and winapi.process_alive(pid) \
        and abs((winapi.process_created(pid) or 0) - float(st.get("created") or -1)) < 2
    beat = float(st.get("heartbeat") or 0)
    return {"running": alive and time.time() - beat < 90, "pid": pid if alive else None, "started": st.get("started"),
            "heartbeat_age_s": round(time.time() - beat, 1) if beat else None, "counters": st.get("counters") or {},
            "autostart": autostart_enabled(), "last_error": st.get("last_error")}


def _command() -> list[str]:
    return paths.background_command("monitor", "run")


def start() -> dict:
    st = status()
    if st["running"]:
        return {"ok": True, "message": "the monitor is already running", **st}
    stop_path().unlink(missing_ok=True)
    last_error = None
    # First try to leave the launcher's job object, so closing the dashboard or a terminal does not
    # take the monitor with it. Not every launcher allows that; then start it the ordinary way.
    for flags in (_DETACHED | 0x01000000, _DETACHED):
        try:
            subprocess.Popen(_command(), creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(paths.OWN_DIR))
            last_error = None
            break
        except OSError as e:
            last_error = e
    if last_error is not None:
        return {"ok": False, "message": f"could not start the monitor: {last_error}"}
    for _ in range(40):
        time.sleep(0.25)
        st = status()
        if st["running"]:
            return {"ok": True, "message": "monitor started", **st}
    return {"ok": False, "message": "the monitor did not report in; see logs\\monitor.log in the state folder", **st}


def stop() -> dict:
    st = status()
    if not st["running"]:
        return {"ok": True, "message": "the monitor is not running", **st}
    stop_path().write_text(str(time.time()), encoding="utf-8")
    for _ in range(60):
        time.sleep(0.25)
        if not status()["running"]:
            stop_path().unlink(missing_ok=True)
            return {"ok": True, "message": "monitor stopped", **status()}
    return {"ok": False, "message": "the monitor did not stop within 15 seconds", **status()}


def autostart_enabled() -> bool:
    return RUN_VALUE in reg.values(reg.HKCU, RUN_KEY)


def set_autostart(on: bool) -> dict:
    """Start the monitor at sign-in (a per-user Run entry; no administrator rights involved)."""
    if not winapi.IS_WINDOWS:
        return {"ok": False, "message": "needs Windows"}
    import winreg
    try:
        with winreg.CreateKeyEx(reg.HKCU, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if on:
                cmd = " ".join(f'"{part}"' if " " in part or part.endswith(".exe") or part.endswith(".py") else part
                               for part in _command())
                winreg.SetValueEx(k, RUN_VALUE, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(k, RUN_VALUE)
                except FileNotFoundError:
                    pass
    except OSError as e:
        return {"ok": False, "message": f"could not change the startup entry: {e}"}
    state = autostart_enabled()
    return {"ok": state == on, "autostart": state,
            "message": "the monitor will start when you sign in" if state else "the monitor will not start by itself"}


class Monitor:
    def __init__(self, store: Store | None = None, log=None):
        self.store = store or Store()
        self.log = log or (lambda m: None)
        self.cfg = paths.load_config()
        self.me = {os.getpid()}
        self.marker = str(paths.OWN_DIR).lower()
        self.known_pids: dict[int, float | None] = {}
        self.seen_conn: set[tuple] = set()
        self.file_marks: dict[str, float] = {}
        self.counters = {"processes": 0, "connections": 0, "events": 0, "files": 0, "findings": 0, "contained": 0}
        self.due: dict[str, float] = {}
        self.last_error: str | None = None
        self.started = time.time()
        self.run_id = self.store.start_run("monitor", winapi.is_elevated())
        self.defender_bad = False

    # ------------------------------------------------------------------ plumbing

    def _emit(self, findings: list[Finding], as_events: bool = False) -> None:
        if not findings:
            return
        if as_events:
            bucket = time.strftime("%Y%m%d%H")
            for f in findings:
                f.kind, f.when = "event", time.time()
                f.key_parts = (*f.key_parts, bucket)  # at most one alert an hour for the same thing
        from .scan import apply_trusted_paths
        apply_trusted_paths(findings, list((self.cfg.get("trusted") or {}).get("paths") or []))
        change = self.store.upsert_findings(self.run_id, [f.to_row() for f in findings], (), mark_gone=False)
        new = change["new"] + change["reopened"]
        if not new:
            return
        self.counters["findings"] += len(new)
        acted = policy.apply(self.store, new, log=self.log, cfg=self.cfg)
        self.counters["contained"] += sum(1 for a in acted if a.get("mode") == "auto" and a.get("ok"))
        done = {a["finding"]: a for a in acted}
        for fid in new:
            f = self.store.get_finding(fid)
            if not f:
                continue
            self.log(f"{f['severity']}: {f['title']}")
            if (self.cfg.get("monitor") or {}).get("notify", True) and SEV_ORDER[f["severity"]] >= SEV_ORDER["medium"]:
                a = done.get(fid)
                note = None
                if a and a.get("mode") == "auto" and a.get("ok"):
                    note = "Contained automatically: " + str(a.get("message"))
                elif a and a.get("mode") == "ask":
                    note = "Waiting for your approval in the HostGuard dashboard."
                notify.for_finding(f, note)

    def _heartbeat(self) -> None:
        data = {"pid": os.getpid(), "created": winapi.process_created(os.getpid()) if winapi.IS_WINDOWS else None,
                "started": self.started, "heartbeat": time.time(), "counters": self.counters, "last_error": self.last_error}
        try:
            paths.atomic_write(state_path(), json.dumps(data))
        except OSError:
            pass

    def _is_due(self, name: str, interval: float) -> bool:
        now = time.time()
        if now >= self.due.get(name, 0):
            self.due[name] = now + max(1.0, float(interval))
            return True
        return False

    # ------------------------------------------------------------------ watchers

    def prime(self) -> None:
        """Take the starting picture so the first pass reports changes, not everything."""
        for pid, _pp, _n in winapi.list_pids():
            self.known_pids[pid] = winapi.process_created(pid)
        for c in winapi.connections():
            self.seen_conn.add((c["pid"], c["raddr"], c["rport"], c["proto"], c["state"] == "LISTEN", c["lport"] if c["state"] == "LISTEN" else 0))
        for root, _d, _s in self._watch_roots():
            self.file_marks[root] = time.time()
        for name, _ids, _cap, _extra, _lvl, _min in c_events.QUERIES:
            if self.store.kv_get("evt:" + name) is None:
                self.store.kv_set("evt:" + name, str(self._last_record(name)))
        if self.store.kv_get("monitor:autoruns") is None:
            try:
                self.store.inventory_sync("autorun", d_persist.inventory(c_persist.collect()["entries"]))
            except util.CollectError:
                pass
            self.store.kv_set("monitor:autoruns", "primed")

    @staticmethod
    def _last_record(log_name: str) -> int:
        rc, out, _err = util.run_cmd([c_events.WEVTUTIL, "qe", log_name, "/c:1", "/rd:true", "/f:xml"], timeout=30)
        evs = c_events.parse_events(out) if rc == 0 else []
        return evs[0]["record"] if evs else 0

    def watch_processes(self) -> None:
        snapshot = winapi.list_pids()
        current = {pid for pid, _pp, _n in snapshot}
        # Our own helpers (PowerShell collectors, wevtutil and whatever they start) are recomputed from
        # the live process tree every pass. Remembering their PIDs instead would, once Windows reuses
        # one of those numbers, hide an unrelated process from the monitor.
        me, grew = {os.getpid()}, True
        while grew:
            grew = False
            for pid, ppid, _name in snapshot:
                if ppid in me and pid not in me:
                    me.add(pid)
                    grew = True
        self.me = me
        fresh = []
        for pid, ppid, name in snapshot:
            if pid in self.known_pids or pid in (0, 4):
                continue
            p = winapi.describe_process(pid, ppid, name)
            self.known_pids[pid] = p.created
            if pid in self.me:
                continue
            fresh.append(p.to_dict())
        for pid in list(self.known_pids):
            if pid not in current:
                del self.known_pids[pid]
        if not fresh:
            return
        self.counters["processes"] += len(fresh)
        parents = []
        for pid in {p["ppid"] for p in fresh}:
            if pid and pid not in {p["pid"] for p in fresh}:
                name = next((n for q, _pp, n in snapshot if q == pid), "")
                if name:
                    parents.append(winapi.describe_process(pid, 0, name, with_token=False).to_dict())
        sig_map = sigs.check(self.store, [p["path"] for p in fresh + parents if p.get("path")])
        new_pids = {p["pid"] for p in fresh}
        found = [f for f in d_proc.detect({"processes": fresh + parents}, sig_map, {"self_pids": self.me})
                 if (f.entity or {}).get("pid") in new_pids]
        self._emit(found, as_events=True)

    def watch_network(self) -> None:
        conns = winapi.connections()
        procs = {}
        fresh = []
        for c in conns:
            key = (c["pid"], c["raddr"], c["rport"], c["proto"], c["state"] == "LISTEN", c["lport"] if c["state"] == "LISTEN" else 0)
            if key in self.seen_conn or c["pid"] in self.me or c["state"] == "TIME_WAIT":
                continue
            self.seen_conn.add(key)
            fresh.append(c)
        if len(self.seen_conn) > 200000:
            self.seen_conn.clear()
        if not fresh:
            return
        self.counters["connections"] += len(fresh)
        names = {pid: (ppid, name) for pid, ppid, name in winapi.list_pids()}
        for c in fresh:
            pid = c["pid"]
            if pid not in procs and pid in names:
                procs[pid] = winapi.describe_process(pid, names[pid][0], names[pid][1], with_token=False).to_dict()
            image = (procs.get(pid) or {}).get("path") or (names.get(pid) or (0, "?"))[1]
            if c["proto"] == "tcp" and c["state"] != "LISTEN" and util.is_public_ip(c["raddr"]):
                self.store.net_observe(image, c["raddr"], c["rport"])
        sig_map = sigs.check(self.store, [p["path"] for p in procs.values() if p.get("path")])
        found = [f for f in d_network.detect({"processes": list(procs.values()), "connections": fresh}, sig_map, {"self_pids": self.me})
                 if f.rule != "net.listen.inventory"]
        self._emit(found, as_events=True)

    def watch_events(self) -> None:
        events: dict[str, list] = {}
        for name in dict.fromkeys(q[0] for q in c_events.QUERIES):
            last = int(self.store.kv_get("evt:" + name) or 0)
            ids = tuple(sorted({i for q in c_events.QUERIES if q[0] == name for i in q[1]}))
            try:
                got = c_events.query(name, ids, days=2, max_events=400, after_record=last)
            except util.CollectError:
                continue
            if got:
                events[name] = got
                self.store.kv_set("evt:" + name, str(max(e["record"] for e in got)))
                self.counters["events"] += len(got)
        if events:
            found = [f for f in d_events.detect({"events": events}, {"own_marker": self.marker}) if f.rule != "evt.service.inventory"]
            self._emit(found)

    def watch_defender(self) -> None:
        try:
            facts = {"defender": util.run_ps("defender", timeout=60) or {}, "registry": c_system.posture_registry()}
        except util.CollectError:
            return
        found = [f for f in d_system.detect_defender(facts) if f.rule in ("defender.realtime_off", "defender.component_off",
                                                                         "defender.script_scanning_off", "defender.tamper_off",
                                                                         "defender.policy_disable", "defender.unavailable")]
        bad = bool(found)
        if bad and not self.defender_bad:
            self._emit(found, as_events=True)
        self.defender_bad = bad

    def watch_persistence(self) -> None:
        try:
            facts = c_persist.collect(include_drivers=False)
        except util.CollectError:
            return
        entries = facts["entries"]
        fresh_keys = set(self.store.inventory_sync("autorun", d_persist.inventory(entries)))
        if not fresh_keys:
            return
        inv = d_persist.inventory(entries)
        fresh = []
        for e in entries:
            key = "|".join([e["kind"], e["location"], e["name"], (e.get("command") or "")[:300]]).lower()
            if key in fresh_keys and key in inv:
                fresh.append(e)
        sig_map = sigs.check(self.store, d_persist.paths_to_check(fresh))
        found = d_persist.detect({"entries": fresh}, sig_map, {"own_marker": self.marker})
        flagged = {tuple(f.key_parts[:3]) for f in found}
        for e in fresh:  # every new autorun is worth a line, even when no rule fires on it
            if (e["kind"], e["location"], e["name"]) in flagged or RUN_VALUE == e["name"]:
                continue
            found.append(Finding(rule="monitor.new_autorun", title=f"New autorun entry: {util.truncate(e['name'], 80)}",
                                 severity="low", confidence="low", category="persistence", collector="monitor",
                                 description="Something registered itself to start automatically. Installers do this; "
                                             "so does anything that wants to survive a restart.",
                                 evidence={"where": e["location"], "command": util.truncate(e.get("command"), 600),
                                           "signature": sigs.describe(sigs.lookup(sig_map, e.get("image")))},
                                 entity={"type": "autorun", "kind": e["kind"], "location": e["location"], "name": e["name"],
                                         "command": e.get("command", ""), "path": e.get("image", "")},
                                 actions=["disable_autorun"], mitre=["T1547"], key_parts=(e["kind"], e["location"], e["name"])))
        self._emit(found, as_events=True)

    def _watch_roots(self) -> list[tuple[str, int, bool]]:
        extra = list((self.cfg.get("monitor") or {}).get("watch_dirs") or [])
        user = os.environ.get("USERPROFILE", "")
        roots = [(os.path.join(user, "Downloads"), 2, True), (os.path.join(user, "Desktop"), 1, False),
                 (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), 1, True),
                 (os.environ.get("PUBLIC", r"C:\Users\Public"), 3, True)]
        roots += [(d, 3, True) for d in extra]
        return [(p, d, s) for p, d, s in roots if p and os.path.isdir(p)]

    def watch_files(self) -> None:
        max_bytes = int((self.cfg.get("scan") or {}).get("max_file_mb", 64)) << 20
        facts = []
        for root, depth, sniff in self._watch_roots():
            since = self.file_marks.get(root, time.time())
            self.file_marks[root] = time.time()
            for path, st, sn in c_files.walk([(root, depth, sniff)], 4000):
                if max(st.st_mtime, st.st_ctime) < since - 1:
                    continue
                try:
                    fact = c_files.describe(path, st, sn, max_bytes)
                except (OSError, ValueError):
                    continue
                if fact:
                    facts.append(fact)
        if not facts:
            return
        self.counters["files"] += len(facts)
        sig_map = sigs.check(self.store, [f["path"] for f in facts if f["type"] == "pe"])
        found = d_files.detect({"files": facts}, sig_map, {})
        if (self.cfg.get("scan") or {}).get("defender_ondemand", True):
            for f in facts:
                if f["type"] not in ("pe", "script"):
                    continue
                res = defender.scan_file(f["path"])
                for threat in res.get("threats") or []:
                    sev, label = d_system.classify_threat(threat)
                    found.append(Finding(rule="file.defender.detected", title=f"Defender identifies a new file as {label}: {f['name']}",
                                         severity="critical" if sev in ("high", "critical") else sev, confidence="high", category="file",
                                         collector="monitor", description=f"Defender's on-demand scanner names it {threat}.",
                                         evidence={"path": f["path"], "threat": threat, "sha256": f.get("sha256")},
                                         entity={"type": "file", "path": f["path"]}, actions=["quarantine"], mitre=["T1204.002"],
                                         key_parts=(f["path"], threat)))
        self._emit(found)

    # ------------------------------------------------------------------ loop

    def step(self) -> None:
        m = self.cfg.get("monitor") or {}
        tasks = (("processes", m.get("process_interval_s", 2), self.watch_processes),
                 ("network", m.get("network_interval_s", 15), self.watch_network),
                 ("files", m.get("files_interval_s", 20), self.watch_files),
                 ("events", m.get("events_interval_s", 30), self.watch_events),
                 ("defender", m.get("defender_interval_s", 60), self.watch_defender),
                 ("persistence", m.get("persistence_interval_s", 300), self.watch_persistence))
        for name, interval, fn in tasks:
            if not self._is_due(name, interval):
                continue
            try:
                fn()
            except Exception as e:  # one failing watcher must not stop the others
                self.last_error = f"{name}: {type(e).__name__}: {e}"
                self.log("error in " + self.last_error)
        if self._is_due("config", 20):
            self.cfg = paths.load_config()
        self._heartbeat()


def run(once: bool = False) -> int:
    if status()["running"]:
        print("the monitor is already running")
        return 0
    logfile = paths.sub("logs") / "monitor.log"

    def log(msg: str) -> None:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
        try:
            with open(logfile, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
        if sys.stdout and sys.stdout.isatty():
            print(line, flush=True)

    mon = Monitor(log=log)
    stop_path().unlink(missing_ok=True)
    log(f"monitor starting (pid {os.getpid()}, containment mode {(mon.cfg.get('containment') or {}).get('mode')})")
    mon.prime()
    mon._heartbeat()
    try:
        while True:
            mon.step()
            if once or stop_path().exists():
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        log(f"monitor stopping: {mon.counters}")
        mon.store.end_run(mon.run_id, {"ran": ["monitor"]}, {"counters": mon.counters, "profile": "monitor"})
        try:
            state_path().unlink()
        except OSError:
            pass
        stop_path().unlink(missing_ok=True)
    return 0
