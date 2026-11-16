"""Optional open-source add-ons. HostGuard works without any of them; each one widens what a scan sees.

Nothing here downloads anything. You fetch a tool from its official release page and unpack it
into the tools folder; from then on scans use it automatically. The command lines below follow
each project's documentation as of November 2026 (YARA 4.6, Hollows Hunter 0.4.1, Hayabusa 4.4).

    YARA + YARA Forge rules   signature matching over the folders malware lands in
    Hollows Hunter            deep scan of every process for implanted or replaced code
    Hayabusa                  thousands of community Sigma rules over the event logs; it needs
                              administrator rights, so it runs as part of "Scan with admin rights"
"""

from __future__ import annotations

import glob
import json
import os
import tempfile

from . import paths, reg, sigs, util
from .model import Finding

CATALOG = [
    {"id": "yara", "title": "YARA with YARA Forge rules", "folder": "yara", "patterns": ["yara64.exe", "yara.exe"],
     "adds": "Signature matching over Downloads, Desktop, Temp and Public with a curated community rule pack.",
     "get": "https://github.com/VirusTotal/yara/releases (the win64 zip) and https://github.com/YARAHQ/yara-forge/releases (the 'core' rule pack)",
     "place": "Put yara64.exe in {dir} and the .yar rule file in {dir}\\rules", "licence": "BSD-3-Clause; rule licences vary"},
    {"id": "hollows_hunter", "title": "Hollows Hunter", "folder": "hollows_hunter", "patterns": ["hollows_hunter64.exe", "hollows_hunter.exe"],
     "adds": "Scans every process it can open for implanted programs, shellcode and replaced modules.",
     "get": "https://github.com/hasherezade/hollows_hunter/releases", "place": "Put hollows_hunter64.exe in {dir}",
     "licence": "BSD-2-Clause"},
    {"id": "hayabusa", "title": "Hayabusa (Sigma rules for event logs)", "folder": "hayabusa",
     "patterns": ["hayabusa-*-win-x64.exe", "hayabusa*.exe"],
     "adds": "Runs thousands of Sigma detection rules over the Windows event logs during 'Scan with admin rights'.",
     "get": "https://github.com/Yamato-Security/hayabusa/releases (the win-x64 zip)",
     "place": "Unzip the whole archive (the exe with its rules and config folders) into {dir}", "licence": "AGPL-3.0; Sigma rules DRL 1.1"},
]
_LEVELS = {"crit": "critical", "critical": "critical", "emer": "critical", "emergency": "critical", "high": "high", "med": "medium",
           "medium": "medium", "low": "low", "info": "info", "informational": "info"}


def tools_dir() -> str:
    return str(paths.sub("tools"))


def find(component: str) -> str | None:
    """Path of an add-on's executable, or None. HOSTGUARD_<NAME> overrides the search (the tests use it)."""
    override = os.environ.get("HOSTGUARD_" + component.upper())
    if override:
        return override if os.path.isfile(override) else None
    entry = next((c for c in CATALOG if c["id"] == component), None)
    if not entry:
        return None
    base = os.path.join(tools_dir(), entry["folder"])
    for pattern in entry["patterns"]:
        hits = sorted(glob.glob(os.path.join(base, pattern)) + glob.glob(os.path.join(base, "*", pattern)), reverse=True)
        if hits:
            return hits[0]
    return None


def yara_rules() -> list[str]:
    base = os.environ.get("HOSTGUARD_YARA_RULES") or os.path.join(tools_dir(), "yara", "rules")
    out = []
    for ext in ("*.yar", "*.yara"):
        out += glob.glob(os.path.join(base, ext)) + glob.glob(os.path.join(base, "*", ext))
    return sorted(out)


def status() -> list[dict]:
    rows = []
    for c in CATALOG:
        exe = find(c["id"])
        folder = os.path.join(tools_dir(), c["folder"])
        detail = exe or ""
        ready = bool(exe)
        if c["id"] == "yara" and exe:
            rules = yara_rules()
            ready = bool(rules)
            detail = f"{exe}; {len(rules)} rule file(s)" + ("" if rules else " (no rules yet, so it is not used)")
        rows.append({"id": c["id"], "title": c["title"], "installed": ready, "detail": detail or "not installed",
                     "adds": c["adds"], "get": c["get"], "place": c["place"].format(dir=folder), "licence": c["licence"]})
    sysmon = any(reg.exists(reg.HKLM, rf"SYSTEM\CurrentControlSet\Services\{n}") for n in ("Sysmon", "Sysmon64"))
    rows.append({"id": "sysmon", "title": "Sysmon", "installed": sysmon, "detail": "service present" if sysmon else "not enabled",
                 "adds": "Process, network and injection telemetry in the event log, which scans and the monitor then read.",
                 "get": "Built into recent Windows 11: use the Sysmon switch under Hardening.", "place": "", "licence": "Microsoft"})
    return rows


# ------------------------------------------------------------------ YARA

def parse_yara(output: str) -> list[dict]:
    """Lines are 'RULE_NAME path'. The path may contain spaces; the rule name cannot."""
    out = []
    for line in (output or "").splitlines():
        line = line.rstrip("\r")
        rule, sep, path = line.partition(" ")
        if sep and rule and path and not rule.startswith(("error", "warning")) and (":" in path or path.startswith("\\")):
            out.append({"rule": rule, "path": path})
    return out


def yara_scan(targets: list[str], max_mb: int = 64, timeout_each: int = 180, log=None) -> list[dict]:
    exe, rules = find("yara"), yara_rules()
    if not exe or not rules:
        return []
    matches: list[dict] = []
    for target in targets:
        if not os.path.exists(target):
            continue
        argv = [exe, "-w", "-r", "-N", "-a", str(timeout_each), "-z", str(max_mb << 20), *rules, target]
        rc, out, err = util.run_cmd(argv, timeout=timeout_each + 60)
        if rc not in (0, 1) and log:
            log(f"YARA on {target}: exit {rc} {util.truncate(err, 160)}")
        matches += parse_yara(out)
    if log:
        log(f"YARA: {len(matches)} rule match(es) in {len(targets)} folder(s)")
    return matches


def yara_findings(matches: list[dict], sig_map: dict | None = None) -> list[Finding]:
    by_file: dict[str, list[str]] = {}
    for m in matches:
        by_file.setdefault(m["path"], []).append(m["rule"])
    out = []
    for path, rules in by_file.items():
        rules = sorted(set(rules))
        sig = sigs.lookup(sig_map or {}, path)
        signed = sigs.is_valid(sig)
        out.append(Finding(rule="file.yara", title=f"YARA rule match: {os.path.basename(path)} ({rules[0]}" + (f" +{len(rules) - 1}" if len(rules) > 1 else "") + ")",
                           severity="low" if signed else "high" if len(rules) >= 2 else "medium", confidence="low" if signed else "medium",
                           category="file", collector="files",
                           description="A community detection rule matched this file's contents. Rules name malware families and "
                                       "attack tools, and some are broad: a match is a reason to look, not a conviction."
                                       + (" The file has a valid publisher signature, which makes a false match more likely." if signed else ""),
                           evidence={"path": path, "rules": rules[:20], "signature": sigs.describe(sig) if sig else None,
                                     "sha256": util.sha256_file(path, 64 << 20)},
                           entity={"type": "file", "path": path}, actions=["quarantine", "defender_scan"], mitre=["T1588.001"],
                           key_parts=(path, ",".join(rules[:5]))))
    return out


# ------------------------------------------------------------------ Hollows Hunter

def parse_hollows(stdout: str) -> dict | None:
    """With -json the tool prints a version banner and then one JSON object."""
    start = (stdout or "").find("{")
    if start < 0:
        return None
    try:
        return json.loads(stdout[start:stdout.rindex("}") + 1])
    except ValueError:
        return None


def hollows_scan(timeout: int = 900, log=None) -> dict | None:
    """Report-only run: -ofilter 2 writes no dumps and no files; nothing is killed or suspended."""
    exe = find("hollows_hunter")
    if not exe:
        return None
    work = tempfile.mkdtemp(prefix="hg-hh-")
    try:
        argv = [exe, "-json", "-quiet", "-ofilter", "2"]
        try:
            import subprocess
            r = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=work, creationflags=util.NO_WINDOW, stdin=subprocess.DEVNULL)
            rc, out = r.returncode, r.stdout.decode("utf-8", "replace")
        except (OSError, subprocess.TimeoutExpired) as e:
            if log:
                log(f"Hollows Hunter did not finish: {e}")
            return None
    finally:
        try:
            os.rmdir(work)
        except OSError:
            pass
    data = parse_hollows(out)
    if data is None:
        if rc == 1:  # documented: scanned, nothing suspicious
            data = {"suspicious_count": 0, "suspicious": []}
        elif log:
            log(f"Hollows Hunter gave no readable report (exit {rc})")
    if data is not None and log:
        log(f"Hollows Hunter: scanned {data.get('scanned_count', '?')}, could not open {data.get('failed_count', '?')}, "
            f"flagged {data.get('suspicious_count', 0)}")
    return data


def hollows_findings(report: dict | None, processes: list[dict], sig_map: dict) -> list[Finding]:
    out = []
    by_pid = {p["pid"]: p for p in processes}
    labels = {"replaced": "a module was replaced in memory (process hollowing)", "hdr_modified": "a module's header was altered",
              "implanted_pe": "a program image was implanted", "implanted_shc": "shellcode was implanted",
              "patched": "code was patched in memory", "iat_hooked": "its import table is hooked",
              "unreachable_file": "its file on disk cannot be read", "other": "other anomalies"}
    for item in (report or {}).get("suspicious") or []:
        pid = item.get("pid")
        p = by_pid.get(pid) or {"pid": pid, "name": item.get("name") or "?", "path": ""}
        what = [text for key, text in labels.items() if item.get(key)]
        strong = any(item.get(k) for k in ("replaced", "implanted_pe", "implanted_shc", "hdr_modified"))
        sig = sigs.lookup(sig_map, p.get("path"))
        signed = sigs.is_valid(sig)
        sev = "low" if signed and not item.get("replaced") else "high" if strong else "medium"
        out.append(Finding(rule="mem.hollows_hunter", title=f"Hollows Hunter flags {p.get('name')}: " + (what[0] if what else "anomalies in memory"),
                           severity=sev, confidence="low" if signed else "medium", category="memory", collector="memory",
                           description="An independent memory scanner found: " + "; ".join(what or ["unspecified anomalies"]) + "."
                                       + (" The program is signed; protected games and security tools trigger this legitimately." if signed else ""),
                           evidence={"process": p.get("name"), "pid": pid, "path": p.get("path"), "signature": sigs.describe(sig) if sig else None,
                                     "indicators": {k: item[k] for k in labels if item.get(k)}, "managed_code": bool(item.get("is_managed"))},
                           entity={"type": "process", "pid": pid, "name": p.get("name"), "path": p.get("path") or "", "created": p.get("created")},
                           actions=["suspend", "kill"], mitre=["T1055", "T1055.012"], key_parts=(p.get("path") or p.get("name"), "hh")))
    return out


# ------------------------------------------------------------------ Hayabusa

def parse_hayabusa(jsonl_text: str, limit: int = 4000) -> list[dict]:
    out = []
    for line in (jsonl_text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("RuleTitle"):
            out.append(rec)
            if len(out) >= limit:
                break
    return out


def hayabusa_findings(records: list[dict]) -> list[Finding]:
    """One finding per Sigma rule that fired, with how often and the latest example."""
    groups: dict[tuple, dict] = {}
    for r in records:
        sev = _LEVELS.get(str(r.get("Level", "")).lower(), "low")
        key = (str(r.get("RuleTitle")), sev)
        g = groups.setdefault(key, {"count": 0, "last": "", "example": r})
        g["count"] += 1
        ts = str(r.get("Timestamp") or "")
        if ts >= g["last"]:
            g["last"], g["example"] = ts, r
    out = []
    for (title, sev), g in groups.items():
        ex = g["example"]
        details = ex.get("Details")
        out.append(Finding(rule="sigma.hayabusa", title=f"Sigma rule fired: {title}", severity=sev, confidence="low" if sev in ("low", "info") else "medium",
                           category="eventlog", collector="eventlogs", kind="event", when=util.parse_time(str(ex.get("Timestamp") or "").replace(" ", "T", 1).replace(" ", "")),
                           description="A community Sigma rule matched events in the Windows logs. Sigma rules are written for many "
                                       "environments and some are noisy on a developer's PC; the example shows what it matched.",
                           evidence={"rule": title, "times": g["count"], "latest": g["last"], "channel": ex.get("Channel"),
                                     "event_id": ex.get("EventID"), "rule_id": ex.get("RuleID"),
                                     "details": util.truncate(json.dumps(details, default=str) if isinstance(details, (dict, list)) else details, 900)},
                           mitre=[], key_parts=(title, sev)))
    out.sort(key=lambda f: -["info", "low", "medium", "high", "critical"].index(f.severity))
    return out[:150]
