"""Decides what to do about a finding: nothing, ask the operator, or act.

The decision is plain code driven by config.json. A language model's opinion can add a request
for approval or (only if you switch that on) lift a finding into automatic handling, but it can
never cancel what a rule decided: text an attacker controls must not be able to talk HostGuard
out of containing them.
"""

from __future__ import annotations

import time

from . import contain, paths
from .model import CONF_ORDER, POSTURE_CATEGORIES, SEV_ORDER

# Tags that mean "a person should look at this, a machine should not act on it".
_NO_AUTO_TAGS = {"trusted-path", "known-installer", "ai-agent-command", "disabled"}


def primary_action(finding: dict, cfg: dict) -> str | None:
    """The one containment step that fits this finding under the current settings."""
    c = cfg.get("containment") or {}
    acts = finding.get("actions") or []
    etype = (finding.get("entity") or {}).get("type")
    if etype == "process":
        want = c.get("process_action", "suspend")
        if want != "none" and want in acts:
            return want
        return "suspend" if want != "none" and "suspend" in acts else None
    if etype == "file" and c.get("file_action", "quarantine") == "quarantine" and "quarantine" in acts:
        return "quarantine"
    if etype == "autorun" and c.get("autorun_action", "disable") == "disable" and "disable_autorun" in acts:
        return "disable_autorun"
    if etype == "ip" and "block_ip" in acts:
        return "block_ip"
    return None


def eligible_for_auto(finding: dict, cfg: dict) -> tuple[bool, str]:
    c = cfg.get("containment") or {}
    if finding.get("category") in POSTURE_CATEGORIES:
        return False, "hardening gaps are never contained automatically"
    tags = set(finding.get("tags") or [])
    if tags & _NO_AUTO_TAGS:
        return False, "tagged " + ", ".join(sorted(tags & _NO_AUTO_TAGS))
    sev_ok = SEV_ORDER[finding["severity"]] >= SEV_ORDER[c.get("auto_min_severity", "critical")]
    conf_ok = CONF_ORDER[finding.get("confidence", "medium")] >= CONF_ORDER[c.get("auto_min_confidence", "high")]
    verdict = finding.get("verdict") or {}
    if (not sev_ok or not conf_ok) and c.get("agent_can_escalate") and verdict.get("verdict") == "malicious" \
            and verdict.get("confidence") == "high" and SEV_ORDER[finding["severity"]] >= SEV_ORDER["high"]:
        return True, "the triage agent judged it malicious and escalation is switched on"
    if not sev_ok:
        return False, f"severity {finding['severity']} is below the automatic threshold"
    if not conf_ok:
        return False, f"confidence {finding.get('confidence')} is below the automatic threshold"
    return True, "meets the automatic containment threshold"


def _auto_count_last_hour(store) -> int:
    since = time.time() - 3600
    return sum(1 for a in store.actions(since=since, limit=500) if str(a["actor"]).startswith("auto") and a["state"] == "done")


def apply(store, finding_ids: list[str], log=None, cfg: dict | None = None) -> list[dict]:
    """Run the policy over these findings. Returns what was done or queued."""
    cfg = cfg or paths.load_config()
    c = cfg.get("containment") or {}
    mode = c.get("mode", "ask")
    out: list[dict] = []
    if mode == "off":
        return out
    budget = int(c.get("max_auto_actions_per_hour", 10)) - _auto_count_last_hour(store)
    isolated = False
    for fid in finding_ids:
        f = store.get_finding(fid)
        if not f or f["status"] != "open":
            continue
        action = primary_action(f, cfg)
        notable = SEV_ORDER[f["severity"]] >= SEV_ORDER["high"] and f["category"] not in POSTURE_CATEGORIES
        auto_ok, why = eligible_for_auto(f, cfg)
        entity = f.get("entity") or {}
        if mode == "auto" and auto_ok and action:
            if budget <= 0:
                why = "the hourly limit on automatic actions was reached, so this one waits for you"
            else:
                res = contain.execute(store, action, entity, actor="auto-policy", finding_id=fid,
                                      reason=f"automatic containment: {why}")
                if res.get("ok"):
                    budget -= 1
                    out.append({"finding": fid, "action": action, "mode": "auto", "ok": True, "message": res.get("message")})
                    if log:
                        log(f"contained automatically: {action} -> {res.get('message')}")
                    if c.get("isolate_on_critical") and f["severity"] == "critical" and not isolated:
                        iso = contain.execute(store, "isolate", {"type": "host"}, actor="auto-policy", finding_id=None,
                                              reason=f"critical finding contained: {f['title']}")
                        isolated = bool(iso.get("ok"))
                        out.append({"finding": fid, "action": "isolate", "mode": "auto", "ok": isolated, "message": iso.get("message")})
                        if log:
                            log(f"network isolation: {iso.get('message')}")
                    continue
                why = res.get("message") or "the automatic action did not go through"
        if action and (notable or (mode == "auto" and auto_ok)):
            aid = contain.propose(store, action, entity, fid, why)
            if aid:
                out.append({"finding": fid, "action": action, "mode": "ask", "ok": None, "action_id": aid, "message": why})
                if log:
                    log(f"waiting for your approval (#{aid}): {action} for '{f['title']}'")
    return out
