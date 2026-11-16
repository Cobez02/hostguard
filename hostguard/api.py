"""What HostGuard's dashboard can ask for: the requests behind every card and switch on the page.

This module knows nothing about HTTP. ui.py serves the page, checks who is asking, and hands
/api/<path> to Api.get or Api.post.

Every switch shows state read back from Windows or from HostGuard's files, never the last click.
Slow or state-changing work runs as a background task whose log the page shows.
"""

from __future__ import annotations

import collections
import secrets
import threading
import time

from . import __version__, agent, components, contain, defender, elevate, harden, monitor, paths, policy, quarantine, report, scan, util, winapi
from .model import ALLOWED, CONTAINED, OPEN, POSTURE_CATEGORIES, RESOLVED, SEV_ORDER
from .store import Store

_ACTIONS = {"suspend", "resume", "kill", "quarantine", "disable_autorun", "block_ip", "unblock_ip", "disable_user", "defender_scan"}
_SETTINGS = {"containment.mode", "containment.auto_min_severity", "containment.auto_min_confidence", "containment.process_action",
             "containment.isolate_on_critical", "containment.agent_can_escalate", "containment.max_auto_actions_per_hour",
             "agent.endpoint", "agent.model", "agent.online_lookups", "agent.keep_alive", "monitor.notify", "trusted.paths",
             "scan.lookback_days", "scan.extra_dirs"}


class ApiError(ValueError):
    """A request the dashboard refuses. The message goes back to the page with a 400."""


class Tasks:
    """Background work with a log the page polls. Containment tasks may overlap; scans may not."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: collections.deque[dict] = collections.deque(maxlen=20)

    def running(self, kind: str | None = None) -> list[str]:
        with self._lock:
            return [t["title"] for t in self._items if t["state"] == "running" and (kind is None or t["kind"] == kind)]

    def start(self, title: str, fn, kind: str = "action", exclusive: bool = False) -> dict:
        with self._lock:
            if exclusive and any(t["state"] == "running" and t["kind"] == kind for t in self._items):
                raise ApiError(f"a {kind} is already running; wait for it to finish")
            task = {"id": secrets.token_hex(5), "title": title, "kind": kind, "state": "running", "log": [],
                    "started": time.time(), "ended": None}
            self._items.appendleft(task)

        def log(line) -> None:
            with self._lock:
                task["log"].append(str(line)[:1200])
                del task["log"][:-200]

        def body() -> None:
            try:
                result = fn(log)
                ok = not (isinstance(result, dict) and result.get("ok") is False)
                if isinstance(result, dict) and result.get("message"):
                    log(("Done: " if ok else "Failed: ") + str(result["message"]))
            except Exception as e:  # shown to the operator, never raised into the server
                log(f"Failed: {type(e).__name__}: {e}")
                ok = False
            with self._lock:
                task["state"] = "done" if ok else "failed"
                task["ended"] = time.time()

        threading.Thread(target=body, daemon=True, name=f"hostguard-task-{task['id']}").start()
        return {"ok": True, "task": task["id"], "message": f"{title}: started"}

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [dict(t, log=list(t["log"])) for t in self._items]


def _trim(f: dict) -> dict:
    v = f.get("verdict") or None
    return {"id": f["id"], "title": f["title"], "severity": f["severity"], "confidence": f["confidence"], "category": f["category"],
            "status": f["status"], "rule": f["rule"], "last_seen": f.get("last_seen"), "first_seen": f.get("first_seen"),
            "tags": f.get("tags") or [], "actions": f.get("actions") or [], "posture": f["category"] in POSTURE_CATEGORIES,
            "verdict": {"verdict": v.get("verdict"), "confidence": v.get("confidence")} if v else None}


class Api:
    def __init__(self) -> None:
        self.tasks = Tasks()
        self._cache: dict[str, tuple[float, object]] = {}
        self._cache_lock = threading.Lock()
        self.last_answer: dict | None = None

    # ------------------------------------------------------------------ helpers

    def _cached(self, name: str, ttl: float, fn):
        with self._cache_lock:
            hit = self._cache.get(name)
            if hit and time.time() - hit[0] < ttl:
                return hit[1]
        value = fn()
        with self._cache_lock:
            self._cache[name] = (time.time(), value)
        return value

    def _drop(self, *names: str) -> None:
        with self._cache_lock:
            for n in names or list(self._cache):
                self._cache.pop(n, None)

    def _agent_state(self) -> dict:
        """Asked in the background: an endpoint that is down takes seconds to say so."""
        with self._cache_lock:
            hit = self._cache.get("agent")
            checking = self._cache.get("agent_checking")
        if hit and time.time() - hit[0] < 60:
            return hit[1]
        if not checking or time.time() - checking[0] > 30:
            with self._cache_lock:
                self._cache["agent_checking"] = (time.time(), True)

            def work():
                state = agent.available()
                with self._cache_lock:
                    self._cache["agent"] = (time.time(), state)
                    self._cache.pop("agent_checking", None)
            threading.Thread(target=work, daemon=True, name="hostguard-agent-check").start()
        return hit[1] if hit else {"ok": None, "message": "checking the model endpoint...", "models": []}

    @staticmethod
    def _store() -> Store:
        return Store()

    @staticmethod
    def _finding(store: Store, fid) -> dict:
        row = store.get_finding(str(fid or ""))
        if not row:
            raise ApiError("that finding no longer exists; refresh the list")
        return row

    # ------------------------------------------------------------------ reading

    def status(self) -> dict:
        store = self._store()
        try:
            ov = report.overview(store)
            rows = store.findings((OPEN, CONTAINED))
            last = ov["last_scan"] or {}
            summary = last.get("summary") or {}
            cov = summary.get("coverage") or {}
            pending = store.actions(state="pending", limit=50)
            titles = {r["id"]: r["title"] for r in rows}
            for p in pending:
                p["finding_title"] = titles.get(p.get("finding_id")) or ""
            actions = [a for a in store.actions(limit=60) if a["state"] != "pending"][:40]
        finally:
            store.close()
        cfg = paths.load_config()
        vault = quarantine.items()
        in_vault = {q["id"] for q in vault}

        def undoable(a: dict) -> bool:
            rb = a.get("rollback") or {}
            if not a["ok"] or a.get("undone") or not rb.get("kind"):
                return False
            return rb["kind"] != "restore" or rb.get("item") in in_vault     # a file already put back cannot be put back again
        d = self._cached("defender", 20, lambda: self._defender_brief())
        return {
            "version": __version__, "verdict": ov["verdict"], "baseline_time": ov["baseline_time"],
            "last_scan": {"ended": last.get("ended"), "profile": last.get("profile"), "seconds": summary.get("seconds"),
                          "elevated": bool(cov.get("elevated")), "notes": (cov.get("notes") or []) + [f"Not read: {g}" for g in cov.get("gaps") or []]}
            if last else None,
            "findings": [_trim(r) for r in rows[:400]],
            "pending": [{"id": p["id"], "action": p["action"], "target": p["target"], "reason": p.get("reason"), "actor": p["actor"],
                         "ts": p["ts"], "finding_id": p.get("finding_id"), "finding_title": p["finding_title"]} for p in pending],
            "actions": [{"id": a["id"], "ts": a["ts"], "actor": a["actor"], "action": a["action"], "state": a["state"], "ok": a["ok"],
                         "undone": a.get("undone"), "undoable": undoable(a),
                         "target": util.truncate(a["target"].get("path") or a["target"].get("name") or a["target"].get("ip") or a["target"].get("type"), 140),
                         "message": util.truncate((a.get("result") or {}).get("message"), 300)} for a in actions],
            "quarantine": [{"id": q["id"], "original": q["original"], "size": q["size"], "when": q["when"], "sha256": q.get("sha256")}
                           for q in vault[:100]],
            "monitor": monitor.status(),
            "isolation": self._cached("isolation", 4, contain.isolation_state),
            "containment": cfg.get("containment"), "agent_cfg": {k: v for k, v in (cfg.get("agent") or {}).items() if k != "api_key"},
            "trusted_paths": (cfg.get("trusted") or {}).get("paths") or [],
            "notify": bool((cfg.get("monitor") or {}).get("notify", True)),
            "agent": self._agent_state(), "answer": self.last_answer, "defender": d,
            "addons": self._cached("addons", 30, components.status),
            "tasks": self.tasks.snapshot(), "scanning": bool(self.tasks.running("scan")),
            "sandboxed_python": paths.python_is_sandboxed(), "state_folder": str(paths.home()), "elevated": winapi.is_elevated(),
        }

    @staticmethod
    def _defender_brief() -> dict:
        try:
            d = util.run_ps("defender", timeout=45) or {}
        except util.CollectError as e:
            return {"error": str(e)}
        st = d.get("status") or {}
        return {"realtime": st.get("RealTimeProtectionEnabled"), "tamper": st.get("IsTamperProtected"),
                "signature_age_days": st.get("AntivirusSignatureAge"), "quick_scan_age_days": st.get("QuickScanAge"),
                "mode": st.get("AMRunningMode"), "version": st.get("AntivirusSignatureVersion")}

    def finding(self, fid: str) -> dict:
        store = self._store()
        try:
            row = self._finding(store, fid)
            history = [a for a in store.actions(limit=300) if a.get("finding_id") == row["id"]][:10]
        finally:
            store.close()
        row["history"] = [{"ts": a["ts"], "actor": a["actor"], "action": a["action"], "state": a["state"],
                           "message": (a.get("result") or {}).get("message")} for a in history]
        return row

    def get(self, path: str, args: dict) -> dict:
        if path == "status":
            return self.status()
        if path == "finding":
            return self.finding(args.get("id", ""))
        if path == "hardening":
            return {"settings": self._cached("hardening", 8, harden.status)}
        raise ApiError("unknown request")

    # ------------------------------------------------------------------ changing

    def post(self, path: str, body: dict) -> dict:
        handler = {
            "scan": self._scan, "elevated-scan": self._elevated_scan, "monitor": self._monitor, "autostart": self._autostart,
            "setting": self._setting, "finding/status": self._finding_status, "contain": self._contain, "approve": self._approve,
            "undo": self._undo, "isolate": self._isolate, "quarantine": self._quarantine, "harden": self._harden,
            "baseline": self._baseline, "triage": self._triage, "ask": self._ask, "defender": self._defender, "selftest": self._selftest,
        }.get(path)
        if handler is None:
            raise ApiError("unknown request")
        return handler(body)

    def _scan(self, body: dict) -> dict:
        profile = body.get("profile") or "quick"
        if profile not in scan.PROFILES:
            raise ApiError("the scan profile must be quick, full or deep")

        def work(log):
            store = Store()
            try:
                summary = scan.run(profile, store, log=log, elevated_data=elevate.load_latest())
                acted = policy.apply(store, summary.get("new_ids") or [], log=log)
                return {"ok": True, "message": summary["verdict"]["text"] + f" ({summary['new']} new, {len(acted)} policy decision(s))"}
            finally:
                store.close()
        return self.tasks.start(f"{profile.capitalize()} scan", work, kind="scan", exclusive=True)

    def _elevated_scan(self, body: dict) -> dict:
        def work(log):
            log("Asking Windows for administrator rights (approve the UAC prompt)...")
            res = elevate.collect()
            if not res.get("ok"):
                return res
            log(res.get("message"))
            store = Store()
            try:
                summary = scan.run("quick", store, log=log, elevated_data=elevate.load_latest())
                policy.apply(store, summary.get("new_ids") or [], log=log)
                return {"ok": True, "message": summary["verdict"]["text"]}
            finally:
                store.close()
        return self.tasks.start("Scan with administrator rights", work, kind="scan", exclusive=True)

    def _monitor(self, body: dict) -> dict:
        on = body.get("on")
        if not isinstance(on, bool):
            raise ApiError("'on' must be true or false")
        return monitor.start() if on else monitor.stop()

    def _autostart(self, body: dict) -> dict:
        on = body.get("on")
        if not isinstance(on, bool):
            raise ApiError("'on' must be true or false")
        return monitor.set_autostart(on)

    def _setting(self, body: dict) -> dict:
        key, value = body.get("key"), body.get("value")
        if key not in _SETTINGS:
            raise ApiError("that setting can't be changed from the dashboard")
        if key == "agent.endpoint" and not str(value).lower().startswith(("http://", "https://")):
            raise ApiError("the endpoint must start with http:// or https://")
        try:
            paths.set_value(key, value)
        except ValueError as e:
            raise ApiError(str(e)) from None
        self._drop("agent", "agent_checking")
        return {"ok": True, "message": "Saved."}

    def _finding_status(self, body: dict) -> dict:
        status = {"allow": ALLOWED, "resolve": RESOLVED, "reopen": OPEN}.get(body.get("status"))
        if status is None:
            raise ApiError("status must be allow, resolve or reopen")
        store = self._store()
        try:
            row = self._finding(store, body.get("id"))
            note = body.get("note")
            store.set_status(row["id"], status, str(note)[:2000] if isinstance(note, str) and note else None)
        finally:
            store.close()
        return {"ok": True, "message": {"allow": "Marked as expected", "resolve": "Marked as dealt with", "reopen": "Reopened"}[body["status"]]}

    def _contain(self, body: dict) -> dict:
        action = body.get("action")
        if action not in _ACTIONS:
            raise ApiError("unknown containment action")
        store = self._store()
        try:
            row = self._finding(store, body.get("id"))
        finally:
            store.close()
        force = body.get("force") is True

        def work(log):
            s = Store()
            try:
                return contain.execute(s, action, row.get("entity") or {}, actor="operator", finding_id=row["id"], force=force,
                                       reason="from the dashboard")
            finally:
                s.close()
        return self.tasks.start(f"{action.replace('_', ' ').capitalize()}: {util.truncate(row['title'], 70)}", work)

    def _approve(self, body: dict) -> dict:
        try:
            action_id = int(body.get("action_id"))
        except (TypeError, ValueError):
            raise ApiError("no action id given") from None
        approve = body.get("approve") is True

        def work(log):
            s = Store()
            try:
                return contain.decide(s, action_id, approve, force=body.get("force") is True)
            finally:
                s.close()
        return self.tasks.start(f"{'Approve' if approve else 'Deny'} request #{action_id}", work)

    def _undo(self, body: dict) -> dict:
        try:
            action_id = int(body.get("action_id"))
        except (TypeError, ValueError):
            raise ApiError("no action id given") from None

        def work(log):
            s = Store()
            try:
                res = contain.undo(s, action_id)
            finally:
                s.close()
            self._drop("isolation", "hardening")
            return res
        return self.tasks.start(f"Undo action #{action_id}", work)

    def _isolate(self, body: dict) -> dict:
        on = body.get("on")
        if not isinstance(on, bool):
            raise ApiError("'on' must be true or false")

        def work(log):
            log("Cutting the network..." if on else "Restoring the network (approve the UAC prompt)...")
            s = Store()
            try:
                res = contain.execute(s, "isolate" if on else "release", {"type": "host"}, actor="operator", reason="from the dashboard")
            finally:
                s.close()
            self._drop("isolation")
            return res
        return self.tasks.start("Isolate this PC from the network" if on else "Restore the network", work)

    def _quarantine(self, body: dict) -> dict:
        what, item = body.get("what"), str(body.get("id") or "")
        if what == "restore":
            res = quarantine.restore(item, overwrite=body.get("overwrite") is True)
        elif what == "delete":
            res = quarantine.delete(item)
        else:
            raise ApiError("'what' must be restore or delete")
        if not res.get("ok"):
            raise ApiError(res.get("message") or "that did not work")
        return res

    def _harden(self, body: dict) -> dict:
        setting, on = body.get("setting"), body.get("on")
        if not isinstance(on, bool) or setting not in {c[0] for c in harden.CATALOG}:
            raise ApiError("unknown hardening switch")

        def work(log):
            log("Asking Windows for administrator rights (approve the UAC prompt)...")
            s = Store()
            try:
                res = harden.set_state(s, setting, on)
            finally:
                s.close()
            self._drop("hardening", "isolation", "defender")
            return res
        return self.tasks.start(f"Hardening: {setting} {'on' if on else 'off'}", work)

    def _baseline(self, body: dict) -> dict:
        store = self._store()
        try:
            n = store.baseline_accept()
            for r in store.findings((OPEN,)):
                if r["rule"].startswith("baseline.new."):
                    store.set_status(r["id"], RESOLVED, "accepted into the baseline")
        finally:
            store.close()
        return {"ok": True, "message": f"Baseline accepted ({n} new item(s) marked as known). Later scans report what changes."}

    def _triage(self, body: dict) -> dict:
        store = self._store()
        try:
            if body.get("id"):
                ids = [self._finding(store, body["id"])["id"]]
            else:
                rows = [r for r in store.findings((OPEN,), min_severity="medium") if r["category"] not in POSTURE_CATEGORIES and not r.get("verdict")]
                rows.sort(key=lambda r: -SEV_ORDER[r["severity"]])
                ids = [r["id"] for r in rows[:8]]
        finally:
            store.close()
        if not ids:
            return {"ok": True, "message": "Nothing to triage: every open finding of medium severity or above already has a verdict."}

        def work(log):
            s = Store()
            done = 0
            try:
                for fid in ids:
                    v = agent.triage(s, fid, log=log)
                    if not v.get("ok"):
                        return v
                    done += 1
                    log(f"{fid[:8]}: {v['verdict']} ({v['confidence']}): {util.truncate(v['summary'], 300)}")
            finally:
                s.close()
            return {"ok": True, "message": f"triaged {done} finding(s)"}
        return self.tasks.start(f"Agent triage of {len(ids)} finding(s)", work, kind="agent", exclusive=True)

    def _ask(self, body: dict) -> dict:
        question = str(body.get("question") or "").strip()
        if not 3 <= len(question) <= 2000:
            raise ApiError("type a question (up to 2000 characters)")

        def work(log):
            s = Store()
            try:
                res = agent.investigate(s, question, log=log)
            finally:
                s.close()
            self.last_answer = {"question": question, "answer": res.get("answer"), "ok": bool(res.get("ok")), "model": res.get("model"),
                                "when": time.time(), "tools_used": res.get("tools_used") or []}
            return {"ok": bool(res.get("ok")), "message": "answered" if res.get("ok") else res.get("message")}
        return self.tasks.start("Agent question", work, kind="agent", exclusive=True)

    def _defender(self, body: dict) -> dict:
        what = body.get("what")
        if what not in ("quick", "full", "update"):
            raise ApiError("'what' must be quick, full or update")

        def work(log):
            log("Running; a full scan can take an hour.")
            res = defender.update_signatures() if what == "update" else defender.start_scan(what)
            self._drop("defender")
            return {"ok": res.get("ok"), "message": res.get("detail")}
        return self.tasks.start({"quick": "Defender quick scan", "full": "Defender full scan", "update": "Update Defender definitions"}[what],
                                work, kind="defender", exclusive=True)

    def _selftest(self, body: dict) -> dict:
        live = body.get("defender") is True

        def work(log):
            import contextlib
            import io
            from . import selftest
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = selftest.run(live_defender=live)
            for line in buf.getvalue().splitlines():
                log(line)
            return {"ok": rc == 0, "message": "self-test passed" if rc == 0 else "self-test found a problem"}
        return self.tasks.start("Self-test", work, kind="selftest", exclusive=True)

