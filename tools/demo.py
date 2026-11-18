"""Serve the dashboard with invented data, for working on the page and for the README pictures.

    python tools/demo.py [--port 8931]

Nothing here reads or changes the PC. Every request is answered from the made-up state below, the
buttons answer politely and do nothing, and the sign-in key file goes to a temporary folder.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ["HOSTGUARD_HOME"] = tempfile.mkdtemp(prefix="hostguard-demo-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hostguard import __version__, addons, components, harden, ui  # noqa: E402
from hostguard.api import ApiError  # noqa: E402

NOW = time.time()
USER = r"C:\Users\alex"
DROPPER = USER + r"\Downloads\invoice_2026.pdf.exe"
IMPLANT = USER + r"\AppData\Local\Temp\svchost_update.exe"
MODEL = "qwen3:14b"


def _finding(fid, severity, title, category, rule, *, status="open", tags=(), actions=(), verdict=None, posture=False, seen=110):
    return {"id": fid, "title": title, "severity": severity, "confidence": "high" if severity in ("high", "critical") else "medium",
            "category": category, "status": status, "rule": rule, "last_seen": NOW - seen, "first_seen": NOW - 1500,
            "tags": list(tags), "actions": list(actions), "posture": posture, "verdict": verdict}


FINDINGS = [
    _finding("a1f47c20d93e5b16", "high", "A program in Downloads pretends to be a document: invoice_2026.pdf.exe", "file", "file.double_extension",
             tags=["unsigned"], actions=["quarantine", "defender_scan"], verdict={"verdict": "malicious", "confidence": "high"}),
    _finding("5be0219a7cd4f803", "high", "Unsigned program running from Temp with a Windows name: svchost_update.exe", "process",
             "proc.impostor", status="contained", tags=["unsigned"], actions=["resume", "kill", "quarantine"],
             verdict={"verdict": "malicious", "confidence": "high"}),
    _finding("c93d5e6f1a2b4478", "medium", "New autorun entry since the baseline: WindowsUpdateHelper", "persistence", "baseline.new.autorun",
             actions=["disable_autorun"], verdict={"verdict": "suspicious", "confidence": "medium"}),
    _finding("e7740b1c58aa9d02", "medium", "New listening port since the baseline: 4444 (svchost_update.exe)", "network", "baseline.new.listener"),
    _finding("0d1b62264fe1c3a9", "low", "Remote access software is running: AnyDesk", "process", "proc.remote_tool", seen=4000),
    _finding("5fd6ca84b2e07d15", "medium", "Remote Desktop is enabled", "posture", "posture.rdp.enabled", posture=True, seen=4000),
    _finding("9e9c7b65d0a1f2e3", "low", "No Attack Surface Reduction rules are configured", "posture", "posture.asr.none", posture=True, seen=4000),
]

DETAIL = {
    "a1f47c20d93e5b16": {
        "description": "The name ends in .pdf.exe, so Windows shows it with a document's name while it runs as a program. It arrived "
                       "from the internet 25 minutes ago and nothing has signed it.",
        "remediation": "Do not open it. Quarantine it, then look at what started around the same time.",
        "confidence": "high", "mitre": ["T1036.007", "T1204.002"], "note": "",
        "evidence": {"path": DROPPER, "size": "2.3 MB", "sha256": "9f2c41d7a05be6638c1f0e7d44b92a15c3e8706fd1b2a94e5c07f3d86a1b2c4d",
                     "signature": "not signed", "downloaded_from": "https://files.example.net/invoice_2026.zip",
                     "zone": "Internet", "created": "2026-11-16T14:02:11-07:00", "defender": "no detection"},
        "verdict": {"model": MODEL, "verdict": "malicious", "confidence": "high",
                    "summary": "The file was downloaded 25 minutes ago, is unsigned, and one minute later a program with a Windows-like "
                               "name started from Temp, opened port 4444 and added a startup entry. Together that is a dropper and its payload.",
                    "evidence": ["file_info: unsigned, 2.3 MB, downloaded from files.example.net at 14:02",
                                 "process_list: svchost_update.exe (pid 9124) started at 14:03 from Temp, parent explorer.exe",
                                 "connections: pid 9124 listens on 0.0.0.0:4444",
                                 "autoruns: HKCU Run 'WindowsUpdateHelper' points at the same file, added at 14:03"]},
        "history": [{"ts": NOW - 118, "actor": "policy", "action": "quarantine", "state": "pending",
                     "message": "waiting for approval"}],
    },
}

PENDING = [{"id": 7, "action": "quarantine", "target": {"type": "file", "path": DROPPER}, "actor": "policy", "ts": NOW - 118,
            "reason": "severity high is below the automatic threshold", "finding_id": "a1f47c20d93e5b16", "finding_title": FINDINGS[0]["title"]}]

ACTIONS = [
    {"id": 6, "ts": NOW - 112, "actor": "policy", "action": "suspend", "state": "done", "ok": 1, "undone": None, "undoable": True,
     "target": "svchost_update.exe (pid 9124)", "message": "suspended 9 threads; the process is intact for investigation and it can be resumed"},
    {"id": 5, "ts": NOW - 2 * 86400, "actor": "operator", "action": "quarantine", "state": "done", "ok": 1, "undone": None, "undoable": True,
     "target": USER + r"\Downloads\free_game_trainer.exe", "message": "quarantined as 20261114-101502-3fa9c1"},
    {"id": 4, "ts": NOW - 2 * 86400 - 400, "actor": "auto", "action": "kill", "state": "refused", "ok": 0, "undone": None, "undoable": False,
     "target": "lsass.exe (pid 1004)", "message": "refused: lsass.exe is a core Windows process"},
]

TASKS = [
    {"id": "t2", "title": "Agent triage of 2 finding(s)", "kind": "agent", "state": "done", "started": NOW - 95, "ended": NOW - 41,
     "log": [f"a1f47c20: {MODEL} is investigating (step 1 of 14)", "a1f47c20: file_info, process_list, connections, autoruns",
             "a1f47c20: malicious (high): a dropper and its payload", "c93d5e6f: suspicious (medium): the entry points at the same file",
             "Done: triaged 2 finding(s)"]},
    {"id": "t1", "title": "Quick scan", "kind": "scan", "state": "done", "started": NOW - 150, "ended": NOW - 114,
     "log": ["scan quick: collecting (elevated: no)", "processes: 231, connections: 96, listeners: 41",
             "persistence: 688 entries in 31 locations", "files: looked at 1498, kept 117",
             "memory: inspected 219 processes, 0 with indicators", "Defender second opinion: asked about 2 file(s), 0 flagged",
             "Done: Suspicious activity: review needed (4 new, 2 policy decision(s))"]},
]

ANSWER = {"question": "What is listening on port 4444, and why?", "ok": True, "model": MODEL, "when": NOW - 30,
          "tools_used": ["connections", "process_info", "file_info", "autoruns"],
          "answer": "Port 4444 is held by svchost_update.exe (pid 9124), which runs from your Temp folder.\n\n"
                    "It is not a Windows component: the real svchost.exe lives in System32 and is signed by Microsoft, and this file "
                    "is unsigned. It started one minute after invoice_2026.pdf.exe was downloaded, and a startup entry named "
                    "WindowsUpdateHelper points at it.\n\nHostGuard has already suspended it. I would quarantine both files and "
                    "switch off the startup entry."}


CANARY = "!Records 4c1e"
CANARY_ROOTS = [("C:\\", "the top of drive C:"), (USER, "your profile folder"), (USER + r"\Desktop", "Desktop"),
                (USER + r"\Documents", "Documents"), (USER + r"\Pictures", "Pictures"), (USER + r"\Downloads", "Downloads"),
                (USER + r"\Music", "Music"), (USER + r"\Videos", "Videos"), (r"C:\Users\Public\Documents", "Public Documents")]


def _status() -> dict:
    return {
        "version": __version__, "baseline_time": NOW - 3 * 86400, "scanning": False, "notify": True, "elevated": False,
        "verdict": {"level": "suspicious", "text": "Suspicious activity: review needed", "open": 4, "posture_open": 2,
                    "counts": {"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 0},
                    "posture_counts": {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0}},
        "last_scan": {"ended": NOW - 114, "profile": "quick", "seconds": 36.2, "elevated": False,
                      "notes": ["143 system processes could not be opened without administrator rights (their names and parents were still checked).",
                                "The Security log needs administrator rights. Use 'Scan with admin rights' to include it."]},
        "findings": FINDINGS, "pending": PENDING, "actions": ACTIONS, "tasks": TASKS, "answer": ANSWER,
        "quarantine": [{"id": "20261114-101502-3fa9c1", "original": USER + r"\Downloads\free_game_trainer.exe", "size": 2411520,
                        "when": NOW - 2 * 86400, "sha256": "4be19c07d2f3a85611e0c9b7a4d36f28905c1e7b3a6d4f8209b5c7e1d3a9f6b2"}],
        "monitor": {"running": True, "pid": 11872, "autostart": True, "last_error": None, "canary_checked": time.time() - 2,
                    "counters": {"processes": 412, "connections": 1280, "findings": 4}},
        "canaries": {"on": True, "record": "ok", "placed": NOW - 3 * 86400 + 900, "checked": time.time() - 1,
                     "folders": len(CANARY_ROOTS), "files": 5 * len(CANARY_ROOTS) - 1, "untouched": 5 * len(CANARY_ROOTS) - 1, "unread": 0,
                     "changed": 0, "folders_changed": 0, "alarm": None,
                     "plan": [{"root": root, "label": label} for root, label in CANARY_ROOTS],
                     "places": [{"path": root.rstrip("\\") + "\\" + CANARY, "label": label, "state": "intact", "note": ""}
                                for root, label in CANARY_ROOTS]},
        "isolation": {"isolated": False, "outbound_blocked": False, "inbound_blocked": False, "one_click_task": True},
        "containment": {"mode": "ask", "auto_min_severity": "critical", "auto_min_confidence": "high", "process_action": "suspend",
                        "isolate_on_critical": False, "agent_can_escalate": False, "max_auto_actions_per_hour": 10},
        "agent_cfg": {"endpoint": "http://127.0.0.1:11434/v1", "model": "", "online_lookups": False},
        "agent": {"ok": True, "local": True, "message": f"ready: {MODEL}", "model": MODEL, "models": [MODEL, "llama3.3:latest"], "loaded": [MODEL]},
        "defender": {"realtime": True, "tamper": True, "signature_age_days": 0, "quick_scan_age_days": 1, "version": "1.463.330.0"},
        "addons": [{"id": c["id"], "title": c["title"], "installed": c["id"] == "yara", "adds": c["adds"], "get": c["get"],
                    "licence": c["licence"], "download": addons.plan(c["id"]), "folder": os.path.join(USER, ".hostguard", "tools", c["folder"]),
                    "managed_version": addons.PINS[c["id"]]["version"] if c["id"] == "yara" else None,
                    "detail": USER + r"\.hostguard\tools\yara\yara64.exe; 1 rule file(s)" if c["id"] == "yara" else "not installed",
                    "place": c["place"].format(dir=USER + r"\.hostguard\tools" + "\\" + c["folder"])} for c in components.CATALOG],
        "trusted_paths": [r"C:\Lab\samples"], "sandboxed_python": False, "state_folder": USER + r"\.hostguard",
    }


class DemoApi:
    def get(self, path: str, args: dict) -> dict:
        if path == "status":
            return _status()
        if path == "hardening":
            on = {"pua_block", "cloud_block_high", "script_block_logging", "one_click_isolation"}
            return {"settings": [{"id": i, "group": g, "title": t, "detail": d, "caveat": c, "on": i in on} for i, g, t, d, c in harden.CATALOG]}
        if path == "finding":
            row = next((dict(f) for f in FINDINGS if f["id"] == args.get("id")), None)
            if row is None:
                raise ApiError("that finding no longer exists; refresh the list")
            return {"description": "", "remediation": "", "mitre": [], "evidence": {}, "history": [], "note": "", **row,
                    **DETAIL.get(row["id"], {})}
        raise ApiError("unknown request")

    def post(self, path: str, body: dict) -> dict:
        return {"ok": True, "message": "This is the demo: nothing was changed."}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8931)
    a = ap.parse_args()
    dash = ui.Dashboard(api=DemoApi(), port=a.port)
    print(f"Demo dashboard, invented data only: {dash.login_url()}", flush=True)
    try:
        dash.serve()
    except KeyboardInterrupt:
        pass
    finally:
        dash.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
