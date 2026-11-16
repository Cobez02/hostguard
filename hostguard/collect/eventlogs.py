"""Reads selected events from the Windows event logs with wevtutil (no PowerShell, no extra rights).

Events come back as raw XML fields, not as the localised message text, so the rules work on any
display language. The Security and Sysmon logs need administrator rights or membership of
"Event Log Readers"; when they cannot be read the scan records that as a coverage gap.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

from .. import paths, util

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
WEVTUTIL = os.path.join(paths.SYSTEM32, "wevtutil.exe")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_EVENT = re.compile(r"<Event[ >].*?</Event>", re.S)

DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
PS_CLASSIC = "Windows PowerShell"
WMI = "Microsoft-Windows-WMI-Activity/Operational"
BITS = "Microsoft-Windows-Bits-Client/Operational"
FIREWALL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
RDP_LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDP_RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
TASKS = "Microsoft-Windows-TaskScheduler/Operational"

YEAR = 365.0
# (log, event ids, newest-N cap, extra XPath on the event body, level filter, minimum look-back in days)
# Rare, high-value events (a service install, a detection, a remote logon, a cleared log) are read
# as far back as the log goes, whatever look-back the scan asked for.
QUERIES: list[tuple[str, tuple[int, ...], int, str, int | None, float]] = [
    ("System", (7045, 104), 600, "", None, YEAR),
    ("System", (7040,), 600, "", None, 0),
    (DEFENDER, (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5001, 5010, 5012, 5013, 3002), 800, "", None, YEAR),
    (DEFENDER, (5004, 5007), 1500, "", None, 90),
    (POWERSHELL, (4104,), 600, "", 3, 0),      # script blocks PowerShell itself marked as suspicious
    (POWERSHELL, (4104,), 600, "", None, 0),   # and the newest of everything else, when full logging is on
    (PS_CLASSIC, (400,), 1500, "", None, 0),
    (WMI, (5861,), 200, "", None, YEAR),
    (BITS, (59,), 600, "", None, 0),
    (FIREWALL, (2003, 2004, 2005, 2071, 2073, 2097, 2099), 800, "", None, 0),
    (RDP_LSM, (21, 25), 400, "", None, YEAR),
    (RDP_RCM, (1149,), 400, "", None, YEAR),
    ("Security", (1102, 4720, 4732, 4728, 4756, 4698, 4697, 4719), 600, "", None, YEAR),
    ("Security", (4625,), 2000, "", None, 0),
    ("Security", (4624,), 1500, "EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']", None, 0),
    ("Security", (4688,), 4000, "", None, 0),
    (SYSMON, (1,), 4000, "", None, 0),
    (SYSMON, (8, 10, 25), 1500, "", None, 0),
]


class LogUnavailable(util.CollectError):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _event(el) -> dict | None:
    sysel = el.find(NS + "System")
    if sysel is None:
        return None
    prov = sysel.find(NS + "Provider")
    tc = sysel.find(NS + "TimeCreated")
    sec = sysel.find(NS + "Security")
    try:
        eid = int(sysel.findtext(NS + "EventID") or 0)
    except ValueError:
        return None
    data: dict[str, str] = {}
    ed = el.find(NS + "EventData")
    if ed is not None:
        for i, x in enumerate(ed):
            data[x.get("Name") or f"p{i}"] = x.text or ""
    ud = el.find(NS + "UserData")
    if ud is not None:
        for x in ud.iter():
            if len(x) == 0 and x.text and x.text.strip():
                data.setdefault(_local(x.tag), x.text)
    return {"id": eid, "time": util.parse_time(tc.get("SystemTime") if tc is not None else None),
            "record": int(sysel.findtext(NS + "EventRecordID") or 0),
            "provider": prov.get("Name") if prov is not None else "",
            "level": int(sysel.findtext(NS + "Level") or 0), "channel": sysel.findtext(NS + "Channel") or "",
            "user_sid": sec.get("UserID") if sec is not None else None, "data": data}


def parse_events(xml_text: str) -> list[dict]:
    out = []
    for chunk in _EVENT.findall(_CTRL.sub("", xml_text or "")):
        try:
            ev = _event(ET.fromstring(chunk))
        except ET.ParseError:
            continue
        if ev:
            out.append(ev)
    return out


def query(log: str, ids: tuple[int, ...], days: float, max_events: int = 500, extra: str = "",
          level: int | None = None, after_record: int | None = None) -> list[dict]:
    """Newest-first events with one of `ids` from the last `days` days."""
    cond = "(" + " or ".join(f"EventID={i}" for i in ids) + ")"
    cond += f" and TimeCreated[timediff(@SystemTime) <= {int(days * 86400 * 1000)}]"
    if level is not None:
        cond += f" and (Level={level})"
    if after_record is not None:
        cond += f" and (EventRecordID > {int(after_record)})"
    xpath = f"*[System[{cond}]]" + (f" and *[{extra}]" if extra else "")
    rc, out, err = util.run_cmd([WEVTUTIL, "qe", log, f"/q:{xpath}", "/f:xml", f"/c:{int(max_events)}", "/rd:true"],
                                timeout=180)
    if rc != 0:
        low = (err or out).lower()
        if rc == 5 or "access is denied" in low:
            raise LogUnavailable(f"{log}: needs administrator rights (or Event Log Readers membership)")
        if rc in (15007, 15001, 2) or "could not be found" in low or "cannot find" in low:
            raise LogUnavailable(f"{log}: this log does not exist on this PC")
        raise util.CollectError(f"{log}: wevtutil failed ({rc}): {(err or out).strip()[:200]}")
    return parse_events(out)


def collect(days: float = 7, log=None, queries=None, elevated_events: dict | None = None) -> dict:
    """{events: {log: [...]}, coverage: {log: text}, gaps: [...]}.

    elevated_events supplies logs that an elevated collection already exported (same format).
    """
    events: dict[str, list[dict]] = {}
    coverage: dict[str, str] = {}
    gaps: list[str] = []
    seen: dict[str, set[int]] = {}
    for name, ids, cap, extra, level, min_days in (queries or QUERIES):
        if coverage.get(name, "").startswith("unavailable"):
            continue
        try:
            got = query(name, ids, max(days, min_days), cap, extra, level)
        except LogUnavailable as e:
            coverage[name] = "unavailable: " + str(e).split(": ", 1)[-1]
            if "does not exist" not in str(e):
                gaps.append(str(e))
            continue
        except util.CollectError as e:
            gaps.append(str(e))
            continue
        bucket = events.setdefault(name, [])
        known = seen.setdefault(name, set())
        for ev in got:
            if ev["record"] not in known:
                known.add(ev["record"])
                bucket.append(ev)
        coverage[name] = f"{len(bucket)} events"
    for name, evs in (elevated_events or {}).items():
        if evs and not events.get(name):
            events[name] = evs
            coverage[name] = f"{len(evs)} events (from the elevated collection)"
            gaps = [g for g in gaps if not g.startswith(name + ":")]
    if log:
        log("event logs: " + ", ".join(f"{k.split('/')[0].replace('Microsoft-Windows-', '')}={v}" for k, v in coverage.items()))
    return {"events": events, "coverage": coverage, "gaps": gaps, "days": days}
