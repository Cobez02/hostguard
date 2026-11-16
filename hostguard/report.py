"""Turns stored findings into something a person can read: console text, Markdown or JSON."""

from __future__ import annotations

import json
import time

from . import util
from .model import OPEN, POSTURE_CATEGORIES, SEV_ORDER, verdict
from .store import Store

_MARK = {"critical": "!!", "high": "! ", "medium": "* ", "low": "- ", "info": "  "}


def overview(store: Store) -> dict:
    """Everything the status line and the dashboard header need."""
    open_rows = store.findings((OPEN,))
    last = store.last_run()
    return {"verdict": verdict(open_rows), "last_scan": last, "counts_by_status": store.counts(),
            "baseline_time": store.baseline_time(), "pending_actions": len(store.actions(state="pending"))}


def _evidence_lines(ev: dict, indent: str = "      ", limit: int = 14) -> list[str]:
    out = []
    for k, v in list(ev.items())[:limit]:
        if isinstance(v, (list, tuple)):
            v = "; ".join(util.truncate(x, 160) for x in v[:8]) + (" ..." if len(v) > 8 else "")
        elif isinstance(v, dict):
            v = json.dumps(v, default=str)
        out.append(f"{indent}{k.replace('_', ' ')}: {util.truncate(v, 420)}")
    return out


def text(store: Store, min_severity: str = "low", include_posture: bool = True, detail: bool = False,
         statuses=(OPEN,)) -> str:
    ov = overview(store)
    v = ov["verdict"]
    last = ov["last_scan"]
    lines = [f"HostGuard: {v['text']}", ""]
    if last:
        s = last.get("summary") or {}
        lines.append(f"Last scan: {util.iso(last.get('ended'))} ({last.get('profile')}, {s.get('seconds', '?')}s, "
                     f"{'elevated' if last.get('elevated') else 'not elevated'})")
    else:
        lines.append("No scan has run yet.")
    c = v["counts"]
    lines.append(f"Open threat findings: {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info")
    pc = v["posture_counts"]
    lines.append(f"Hardening gaps: {pc['high']} high, {pc['medium']} medium, {pc['low']} low, {pc['info']} info")
    if ov["pending_actions"]:
        lines.append(f"Containment actions waiting for your approval: {ov['pending_actions']}")
    lines.append("Baseline: " + (f"accepted {util.iso(ov['baseline_time'])}" if ov["baseline_time"] else
                                 "not set (run 'baseline accept' once the findings below look right)"))
    rows = [r for r in store.findings(statuses) if SEV_ORDER[r["severity"]] >= SEV_ORDER[min_severity]]
    threat = [r for r in rows if r["category"] not in POSTURE_CATEGORIES]
    posture = [r for r in rows if r["category"] in POSTURE_CATEGORIES]
    for title, group in (("FINDINGS", threat), ("HARDENING", posture if include_posture else [])):
        if not group:
            continue
        lines += ["", title]
        for r in group:
            tags = f" [{', '.join(r['tags'])}]" if r.get("tags") else ""
            lines.append(f" {_MARK[r['severity']]}{r['severity']:<8} {r['id'][:8]}  {r['title']}{tags}")
            if detail:
                if r.get("description"):
                    lines.append(f"      {r['description']}")
                lines += _evidence_lines(r.get("evidence") or {})
                if r.get("verdict"):
                    vd = r["verdict"]
                    lines.append(f"      agent: {vd.get('verdict')} ({vd.get('confidence')}): {util.truncate(vd.get('summary'), 400)}")
    if last:
        cov = (last.get("summary") or {}).get("coverage") or {}
        notes = (cov.get("notes") or []) + [f"Not read: {g}" for g in cov.get("gaps") or []]
        if notes:
            lines += ["", "WHAT THIS SCAN COULD NOT SEE"] + [f"  {n}" for n in dict.fromkeys(notes)]
    return "\n".join(lines)


def finding_text(r: dict) -> str:
    lines = [f"{r['title']}", f"id {r['id']}   {r['severity']} / confidence {r['confidence']}   {r['category']}   status {r['status']}",
             f"rule {r['rule']}   first seen {util.iso(r.get('first_seen'))}   last seen {util.iso(r.get('last_seen'))}"]
    if r.get("mitre"):
        lines.append("ATT&CK: " + ", ".join(r["mitre"]))
    if r.get("description"):
        lines += ["", r["description"]]
    lines += ["", "Evidence"] + _evidence_lines(r.get("evidence") or {}, "  ", 40)
    if r.get("remediation"):
        lines += ["", "What to do", "  " + r["remediation"]]
    if r.get("actions"):
        lines += ["", "Containment available: " + ", ".join(r["actions"])]
    if r.get("note"):
        lines += ["", "Note: " + r["note"]]
    vd = r.get("verdict")
    if vd:
        lines += ["", f"Agent verdict: {vd.get('verdict')} (confidence {vd.get('confidence')}, model {vd.get('model')})",
                  "  " + str(vd.get("summary") or "")]
        for step in vd.get("evidence") or []:
            lines.append("  - " + util.truncate(step, 300))
        if vd.get("recommended_actions"):
            lines.append("  recommends: " + ", ".join(vd["recommended_actions"]))
    return "\n".join(lines)


def markdown(store: Store) -> str:
    ov = overview(store)
    v = ov["verdict"]
    last = ov["last_scan"] or {}
    s = last.get("summary") or {}
    out = [f"# HostGuard report: {v['text']}", "",
           f"Generated {util.iso(time.time())}. Last scan {util.iso(last.get('ended'))} ({last.get('profile', 'none')}).", "",
           "| Severity | Threat findings | Hardening gaps |", "|---|---|---|"]
    for sev in ("critical", "high", "medium", "low", "info"):
        out.append(f"| {sev} | {v['counts'][sev]} | {v['posture_counts'][sev]} |")
    rows = store.findings((OPEN,))
    for title, pick in (("Findings", lambda r: r["category"] not in POSTURE_CATEGORIES),
                        ("Hardening", lambda r: r["category"] in POSTURE_CATEGORIES)):
        group = [r for r in rows if pick(r)]
        if not group:
            continue
        out += ["", f"## {title}", ""]
        for r in group:
            out += [f"### [{r['severity']}] {r['title']}", "", r.get("description") or "", ""]
            for k, val in (r.get("evidence") or {}).items():
                if isinstance(val, (list, dict)):
                    val = json.dumps(val, default=str)
                out.append(f"- **{k.replace('_', ' ')}**: `{util.truncate(val, 500)}`")
            if r.get("verdict"):
                out.append(f"- **agent verdict**: {r['verdict'].get('verdict')}: {r['verdict'].get('summary')}")
            out.append("")
    cov = s.get("coverage") or {}
    notes = (cov.get("notes") or []) + [f"Not read: {g}" for g in cov.get("gaps") or []]
    if notes:
        out += ["## What the scan could not see", ""] + [f"- {n}" for n in dict.fromkeys(notes)]
    return "\n".join(out) + "\n"
