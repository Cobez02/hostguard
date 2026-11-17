"""SQLite state: scan runs, findings, the inventory baseline, the action log and small caches.

One file (hostguard.db) in the state folder. The CLI, the monitor and the dashboard all
open it at once, so it runs in WAL mode and every write goes through one lock per process.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from . import paths
from .model import ALLOWED, CONTAINED, GONE, OPEN, RESOLVED, SEV_ORDER, STATUSES

EVENT_TTL_DAYS = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, started REAL, ended REAL, profile TEXT, elevated INTEGER,
  collectors TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, rule TEXT, title TEXT, severity TEXT, confidence TEXT, category TEXT,
  description TEXT, evidence TEXT, entity TEXT, mitre TEXT, remediation TEXT, actions TEXT,
  kind TEXT, collector TEXT, tags TEXT, event_time REAL,
  first_seen REAL, last_seen REAL, last_run INTEGER, seen_count INTEGER DEFAULT 1,
  status TEXT DEFAULT 'open', note TEXT DEFAULT '', status_time REAL, verdict TEXT);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS inventory (
  kind TEXT, key TEXT, data TEXT, first_seen REAL, last_seen REAL, baseline INTEGER DEFAULT 0,
  PRIMARY KEY (kind, key));
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, target TEXT, finding_id TEXT,
  state TEXT DEFAULT 'done', ok INTEGER, result TEXT, rollback TEXT, undone REAL, reason TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS actions_state ON actions(state);
CREATE TABLE IF NOT EXISTS sigcache (
  path TEXT PRIMARY KEY, size INTEGER, mtime REAL, status TEXT, signer TEXT, issuer TEXT, is_os INTEGER,
  checked REAL);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS netobs (
  image TEXT, raddr TEXT, rport INTEGER, first_seen REAL, last_seen REAL, hits INTEGER DEFAULT 1,
  PRIMARY KEY (image, raddr, rport));
"""

_JSON_COLS = ("evidence", "entity", "mitre", "actions", "tags", "verdict")


def _row_to_finding(row: sqlite3.Row) -> dict:
    d = dict(row)
    for c in _JSON_COLS:
        raw = d.get(c)
        try:
            d[c] = json.loads(raw) if raw else ([] if c in ("mitre", "actions", "tags") else None if c == "verdict" else {})
        except ValueError:
            d[c] = {}
    return d


def _row_to_action(row: sqlite3.Row) -> dict:
    d = dict(row)
    for c in ("target", "result", "rollback"):
        try:
            d[c] = json.loads(d[c]) if d.get(c) else {}
        except ValueError:
            d[c] = {"raw": d[c]}
    return d


class Store:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else paths.home() / "hostguard.db"
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), timeout=20, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(_SCHEMA)
            self._db.commit()
        self._migrate()

    def _migrate(self) -> None:
        """One-time repairs of data written by earlier versions."""
        if self.kv_get("listener_keys") == "2":
            return
        # A listener's key used to end in its program's full path when that could be read and in the
        # bare file name when it could not. A scan with administrator data could read more paths, so
        # every system port looked new. Keys now always end in the file name; merge the old ones.
        sep = chr(92)
        with self._lock, self._db:
            for row in self._db.execute("SELECT key, baseline, first_seen FROM inventory WHERE kind='listener'").fetchall():
                proto, _, rest = row["key"].partition("|")
                port, _, image = rest.partition("|")
                new = f"{proto}|{port}|{image.replace('/', sep).rsplit(sep, 1)[-1]}"
                if new == row["key"]:
                    continue
                twin = self._db.execute("SELECT baseline, first_seen FROM inventory WHERE kind='listener' AND key=?", (new,)).fetchone()
                if twin:
                    self._db.execute("UPDATE inventory SET baseline=?, first_seen=? WHERE kind='listener' AND key=?",
                                     (max(twin["baseline"], row["baseline"]), min(twin["first_seen"], row["first_seen"]), new))
                    self._db.execute("DELETE FROM inventory WHERE kind='listener' AND key=?", (row["key"],))
                else:
                    self._db.execute("UPDATE inventory SET key=? WHERE kind='listener' AND key=?", (new, row["key"]))
        self.kv_set("listener_keys", "2")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ runs

    def start_run(self, profile: str, elevated: bool) -> int:
        with self._lock, self._db:
            cur = self._db.execute("INSERT INTO runs (started, profile, elevated) VALUES (?, ?, ?)",
                                   (time.time(), profile, int(elevated)))
            return int(cur.lastrowid)

    def end_run(self, run_id: int, collectors: dict, summary: dict) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE runs SET ended=?, collectors=?, summary=? WHERE id=?",
                             (time.time(), json.dumps(collectors), json.dumps(summary, default=str), run_id))

    def last_run(self, profile: str | None = None) -> dict | None:
        """The most recent finished scan (the monitor's own run records are not scans)."""
        q = "SELECT * FROM runs WHERE ended IS NOT NULL"
        args: tuple = ()
        if profile:
            q += " AND profile=?"
            args = (profile,)
        else:
            q += " AND profile != 'monitor'"
        with self._lock:
            row = self._db.execute(q + " ORDER BY id DESC LIMIT 1", args).fetchone()
        if not row:
            return None
        d = dict(row)
        for c in ("collectors", "summary"):
            try:
                d[c] = json.loads(d[c]) if d[c] else {}
            except ValueError:
                d[c] = {}
        return d

    # ------------------------------------------------------------------ findings

    def upsert_findings(self, run_id: int, rows: list[dict], ran_collectors: list[str] | tuple = (),
                        mark_gone: bool = True) -> dict:
        """Record what a run found.

        A finding keeps its status across runs. One that had gone away or been resolved and is
        observed again reopens. State findings from a collector that ran but did not report them
        this time become 'gone'.
        """
        now = time.time()
        new: list[str] = []
        reopened: list[str] = []
        with self._lock, self._db:
            for r in rows:
                cur = self._db.execute("SELECT status FROM findings WHERE id=?", (r["id"],)).fetchone()
                payload = (r["rule"], r["title"], r["severity"], r["confidence"], r["category"], r["description"],
                           json.dumps(r["evidence"], default=str), json.dumps(r["entity"], default=str),
                           json.dumps(r["mitre"]), r["remediation"], json.dumps(r["actions"]), r["kind"],
                           r["collector"], json.dumps(r["tags"]), r.get("event_time"))
                if cur is None:
                    self._db.execute(
                        "INSERT INTO findings (rule, title, severity, confidence, category, description, evidence,"
                        " entity, mitre, remediation, actions, kind, collector, tags, event_time, id, first_seen,"
                        " last_seen, last_run, status, status_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        payload + (r["id"], now, now, run_id, OPEN, now))
                    new.append(r["id"])
                    continue
                status = cur["status"]
                if status == GONE or (status == RESOLVED and r["kind"] == "state"):
                    status = OPEN
                    reopened.append(r["id"])
                self._db.execute(
                    "UPDATE findings SET rule=?, title=?, severity=?, confidence=?, category=?, description=?,"
                    " evidence=?, entity=?, mitre=?, remediation=?, actions=?, kind=?, collector=?, tags=?,"
                    " event_time=?, last_seen=?, last_run=?, seen_count=seen_count+1, status=?,"
                    " status_time=CASE WHEN status=? THEN status_time ELSE ? END WHERE id=?",
                    payload + (now, run_id, status, status, now, r["id"]))
            if mark_gone and ran_collectors:
                marks = ",".join("?" * len(ran_collectors))
                self._db.execute(
                    f"UPDATE findings SET status=?, status_time=? WHERE kind='state' AND status=? "
                    f"AND collector IN ({marks}) AND last_run != ?",
                    (GONE, now, OPEN, *ran_collectors, run_id))
            # An event stays on the list for a month after HostGuard first learned of it, however old
            # the event itself is: a first scan must be able to surface something from last quarter.
            self._db.execute(
                "UPDATE findings SET status=?, status_time=? WHERE kind='event' AND status=? AND first_seen < ?",
                (GONE, now, OPEN, now - EVENT_TTL_DAYS * 86400))
        return {"new": new, "reopened": reopened}

    def findings(self, statuses: list[str] | tuple | None = (OPEN,), min_severity: str | None = None,
                 category: str | None = None, limit: int = 2000) -> list[dict]:
        q = "SELECT * FROM findings WHERE 1=1"
        args: list = []
        if statuses:
            q += f" AND status IN ({','.join('?' * len(statuses))})"
            args += list(statuses)
        if category:
            q += " AND category=?"
            args.append(category)
        with self._lock:
            rows = [_row_to_finding(r) for r in self._db.execute(q, args).fetchall()]
        if min_severity:
            floor = SEV_ORDER[min_severity]
            rows = [r for r in rows if SEV_ORDER.get(r["severity"], 0) >= floor]
        rows.sort(key=lambda r: (-SEV_ORDER.get(r["severity"], 0), -(r["last_seen"] or 0)))
        return rows[:limit]

    def get_finding(self, fid: str) -> dict | None:
        """By full id or an unambiguous prefix (at least 4 characters)."""
        fid = (fid or "").strip().lower()
        with self._lock:
            row = self._db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
            if row is None and len(fid) >= 4:
                rows = self._db.execute("SELECT * FROM findings WHERE id LIKE ? LIMIT 2", (fid + "%",)).fetchall()
                row = rows[0] if len(rows) == 1 else None
        return _row_to_finding(row) if row else None

    def set_status(self, fid: str, status: str, note: str | None = None) -> bool:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        with self._lock, self._db:
            if note is None:
                cur = self._db.execute("UPDATE findings SET status=?, status_time=? WHERE id=?",
                                       (status, time.time(), fid))
            else:
                cur = self._db.execute("UPDATE findings SET status=?, status_time=?, note=? WHERE id=?",
                                       (status, time.time(), note[:2000], fid))
            return cur.rowcount > 0

    def set_verdict(self, fid: str, verdict: dict) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE findings SET verdict=? WHERE id=?", (json.dumps(verdict, default=str), fid))

    def counts(self) -> dict:
        with self._lock:
            rows = self._db.execute("SELECT status, COUNT(*) AS n FROM findings GROUP BY status").fetchall()
        return {r["status"]: r["n"] for r in rows}

    # ------------------------------------------------------------------ inventory and baseline

    def inventory_sync(self, kind: str, items: dict[str, dict]) -> list[str]:
        """Record what exists now. Returns the keys that were never seen before."""
        now = time.time()
        fresh: list[str] = []
        with self._lock, self._db:
            known = {r["key"] for r in self._db.execute("SELECT key FROM inventory WHERE kind=?", (kind,))}
            for key, data in items.items():
                blob = json.dumps(data, default=str, sort_keys=True)
                if key in known:
                    self._db.execute("UPDATE inventory SET data=?, last_seen=? WHERE kind=? AND key=?",
                                     (blob, now, kind, key))
                else:
                    self._db.execute("INSERT INTO inventory (kind, key, data, first_seen, last_seen, baseline)"
                                     " VALUES (?,?,?,?,?,0)", (kind, key, blob, now, now))
                    fresh.append(key)
        return fresh

    def inventory(self, kind: str | None = None, only_new: bool = False) -> list[dict]:
        q = "SELECT * FROM inventory WHERE 1=1"
        args: list = []
        if kind:
            q += " AND kind=?"
            args.append(kind)
        if only_new:
            q += " AND baseline=0"
        with self._lock:
            rows = self._db.execute(q + " ORDER BY first_seen DESC", args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["data"] = json.loads(d["data"]) if d["data"] else {}
            except ValueError:
                d["data"] = {}
            out.append(d)
        return out

    def baseline_time(self) -> float | None:
        v = self.kv_get("baseline_time")
        return float(v) if v else None

    def baseline_accept(self) -> int:
        """Everything in the inventory right now becomes "known". Later scans flag what is new."""
        with self._lock, self._db:
            cur = self._db.execute("UPDATE inventory SET baseline=1 WHERE baseline=0")
            n = cur.rowcount
        self.kv_set("baseline_time", str(time.time()))
        return n

    # ------------------------------------------------------------------ actions

    def log_action(self, actor: str, action: str, target: dict, finding_id: str | None = None,
                   state: str = "done", ok: bool | None = None, result: dict | None = None,
                   rollback: dict | None = None, reason: str = "") -> int:
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO actions (ts, actor, action, target, finding_id, state, ok, result, rollback, reason)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (time.time(), actor, action, json.dumps(target, default=str), finding_id, state,
                 None if ok is None else int(ok), json.dumps(result or {}, default=str),
                 json.dumps(rollback or {}, default=str), reason[:1000]))
            return int(cur.lastrowid)

    def update_action(self, action_id: int, **fields) -> None:
        cols, args = [], []
        for k, v in fields.items():
            if k in ("result", "rollback", "target"):
                v = json.dumps(v or {}, default=str)
            elif k == "ok" and v is not None:
                v = int(bool(v))
            elif k not in ("state", "undone", "actor", "reason", "ok"):
                raise ValueError(f"can't update action field {k!r}")
            cols.append(f"{k}=?")
            args.append(v)
        if not cols:
            return
        with self._lock, self._db:
            self._db.execute(f"UPDATE actions SET {', '.join(cols)} WHERE id=?", (*args, action_id))

    def get_action(self, action_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM actions WHERE id=?", (int(action_id),)).fetchone()
        return _row_to_action(row) if row else None

    def actions(self, state: str | None = None, limit: int = 200, since: float | None = None) -> list[dict]:
        q = "SELECT * FROM actions WHERE 1=1"
        args: list = []
        if state:
            q += " AND state=?"
            args.append(state)
        if since:
            q += " AND ts>=?"
            args.append(since)
        with self._lock:
            rows = self._db.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
        return [_row_to_action(r) for r in rows]

    def pending_for(self, finding_id: str, action: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM actions WHERE finding_id=? AND action=? AND state='pending'"
                                   " ORDER BY id DESC LIMIT 1", (finding_id, action)).fetchone()
        return _row_to_action(row) if row else None

    # ------------------------------------------------------------------ signature cache

    def sig_get(self, path: str, size: int, mtime: float) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM sigcache WHERE path=?", (path.lower(),)).fetchone()
        if row and row["size"] == size and abs((row["mtime"] or 0) - mtime) < 0.01:
            return {"status": row["status"], "signer": row["signer"], "issuer": row["issuer"],
                    "is_os": bool(row["is_os"])}
        return None

    def sig_put(self, path: str, size: int, mtime: float, sig: dict) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO sigcache (path, size, mtime, status, signer, issuer, is_os,"
                             " checked) VALUES (?,?,?,?,?,?,?,?)",
                             (path.lower(), size, mtime, sig.get("status", ""), sig.get("signer", ""),
                              sig.get("issuer", ""), int(bool(sig.get("is_os"))), time.time()))

    def sig_clear(self) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM sigcache")

    # ------------------------------------------------------------------ misc

    def kv_get(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def kv_set(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, value))

    def net_observe(self, image: str, raddr: str, rport: int) -> bool:
        """Remember that `image` talked to raddr:rport. True the first time."""
        now = time.time()
        key = (image.lower(), raddr, int(rport))
        with self._lock, self._db:
            row = self._db.execute("SELECT 1 FROM netobs WHERE image=? AND raddr=? AND rport=?", key).fetchone()
            if row:
                self._db.execute("UPDATE netobs SET last_seen=?, hits=hits+1 WHERE image=? AND raddr=? AND rport=?",
                                 (now, *key))
                return False
            self._db.execute("INSERT INTO netobs (image, raddr, rport, first_seen, last_seen) VALUES (?,?,?,?,?)",
                             (*key, now, now))
            return True
