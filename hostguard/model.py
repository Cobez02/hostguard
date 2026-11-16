"""What a finding is."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
CONF_ORDER = {"low": 0, "medium": 1, "high": 2}

# Categories that describe how well the PC is locked down, not whether something got in.
# They are reported, but they never raise the compromise verdict.
POSTURE_CATEGORIES = {"posture"}

# Finding statuses.
OPEN = "open"            # seen and not yet dealt with
GONE = "gone"            # a state finding that the latest scan no longer observed
ALLOWED = "allowed"      # you marked it as expected; it stays suppressed while it looks the same
RESOLVED = "resolved"    # you dealt with it; it reopens if it is observed again
CONTAINED = "contained"  # a containment action succeeded on it
STATUSES = (OPEN, GONE, ALLOWED, RESOLVED, CONTAINED)


@dataclass
class Finding:
    rule: str                    # stable rule id, e.g. "proc.lolbin.download_cradle"
    title: str
    severity: str                # info | low | medium | high | critical
    category: str                # process | network | persistence | defender | posture | eventlog | file | memory | account | config | browser
    description: str = ""
    confidence: str = "medium"   # low | medium | high: how sure the rule is that this is malicious
    evidence: dict = field(default_factory=dict)
    entity: dict = field(default_factory=dict)      # what containment would act on: {"type": "process", "pid": ..}
    mitre: list = field(default_factory=list)       # ATT&CK technique ids
    remediation: str = ""
    actions: list = field(default_factory=list)     # containment actions that make sense here
    kind: str = "state"          # state: re-checked every scan | event: happened once, at `when`
    collector: str = ""
    key_parts: tuple = ()        # what makes this the same finding next time (never a PID)
    when: float | None = None
    tags: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEV_ORDER:
            raise ValueError(f"bad severity {self.severity!r} in rule {self.rule}")
        if self.confidence not in CONF_ORDER:
            raise ValueError(f"bad confidence {self.confidence!r} in rule {self.rule}")
        if self.kind not in ("state", "event"):
            raise ValueError(f"bad kind {self.kind!r} in rule {self.rule}")

    @property
    def key(self) -> str:
        raw = "|".join([self.rule, *[str(p).lower() for p in self.key_parts]])
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def to_row(self) -> dict:
        return {"id": self.key, "rule": self.rule, "title": self.title, "severity": self.severity,
                "confidence": self.confidence, "category": self.category, "description": self.description,
                "evidence": self.evidence, "entity": self.entity, "mitre": list(self.mitre),
                "remediation": self.remediation, "actions": list(self.actions), "kind": self.kind,
                "collector": self.collector, "event_time": self.when, "tags": list(self.tags)}


def cap_severity(sev: str, ceiling: str) -> str:
    return sev if SEV_ORDER[sev] <= SEV_ORDER[ceiling] else ceiling


def bump(sev: str, steps: int = 1) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, SEV_ORDER[sev] + steps)]


def verdict(findings: list[dict]) -> dict:
    """The one-line answer to "am I compromised?" from the open findings.

    Posture findings (hardening gaps) are counted separately: a PC can be badly configured and
    still clean, or well configured and still compromised.
    """
    threat = [f for f in findings if f.get("status", OPEN) == OPEN and f["category"] not in POSTURE_CATEGORIES]
    posture = [f for f in findings if f.get("status", OPEN) == OPEN and f["category"] in POSTURE_CATEGORIES]
    counts = {s: 0 for s in SEVERITIES}
    for f in threat:
        counts[f["severity"]] += 1
    strong_critical = [f for f in threat if f["severity"] == "critical" and f.get("confidence") != "low"]
    if strong_critical:
        level, text = "compromised", "Signs of compromise: act now"
    elif counts["critical"] or counts["high"]:
        level, text = "suspicious", "Suspicious activity: review needed"
    elif counts["medium"]:
        level, text = "review", "No clear compromise; some items to review"
    else:
        level, text = "clean", "No signs of compromise found"
    return {"level": level, "text": text, "counts": counts,
            "posture_counts": {s: sum(1 for f in posture if f["severity"] == s) for s in SEVERITIES},
            "open": len(threat), "posture_open": len(posture)}
