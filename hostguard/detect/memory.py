"""Collects and judges signs of code injected into running processes.

Two indicators, both read-only (see winapi.inspect_memory):
- a thread that started in memory no file on disk backs
- an executable region that is private to the process yet starts with a program header

Protected games and DRM do both on purpose, so a valid publisher signature lowers the severity
and the text says why.
"""

from __future__ import annotations

from .. import sigs, util, winapi
from ..model import Finding

# Never opened for reading: either Windows forbids it, or doing so is itself what credential
# thieves do and would rightly set off alarms.
NEVER_INSPECT = {"lsass.exe", "lsaiso.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                 "system", "registry", "secure system", "memory compression", "msmpeng.exe", "nissrv.exe",
                 "mpdefendercoreservice.exe", "securityhealthservice.exe", "vmmem", "vmmemwsl"}


def collect(processes: list[dict], self_pids=(), log=None) -> dict:
    results, denied = [], 0
    if not winapi.IS_WINDOWS:
        return {"results": [], "inspected": 0, "denied": 0}
    tids = winapi.thread_ids()
    for p in processes:
        name = (p.get("name") or "").lower()
        if p["pid"] in (0, 4) or p["pid"] in self_pids or name in NEVER_INSPECT or not p.get("accessible"):
            continue
        try:
            r = winapi.inspect_memory(p["pid"], tids.get(p["pid"], []))
        except OSError:
            denied += 1
            continue
        if r["unbacked_threads"] or r["private_pe"]:
            results.append({"pid": p["pid"], "name": p.get("name"), "path": p.get("path"), "created": p.get("created"),
                            "cmdline": p.get("cmdline"), **r})
    inspected = sum(1 for p in processes if p.get("accessible")) - denied
    if log:
        log(f"memory: inspected {inspected} processes, {len(results)} with indicators, {denied} not readable")
    return {"results": results, "inspected": inspected, "denied": denied}


def detect(facts: dict, sig_map: dict[str, dict], ctx: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    for r in facts.get("results") or []:
        sig = sigs.lookup(sig_map, r.get("path"))
        signed = sigs.is_valid(sig)
        threads, regions = r.get("unbacked_threads") or [], r.get("private_pe") or []
        with_header = [t for t in threads if t.get("pe_header")]
        ent = {"type": "process", "pid": r["pid"], "name": r.get("name"), "path": r.get("path") or "", "created": r.get("created")}
        ev = {"process": r.get("name"), "pid": r["pid"], "path": r.get("path"), "signature": sigs.describe(sig),
              "command_line": util.truncate(r.get("cmdline"), 500), "threads_in_unbacked_memory": len(threads),
              "of_which_in_a_hidden_module": len(with_header), "hidden_modules": len(regions),
              "examples": threads[:4] + regions[:4]}
        if signed:
            sev, conf = "low", "low"
            tail = (f" The program is {sigs.describe(sig)}. Games with anti-tamper protection, DRM and some "
                    "security products load code this way on purpose, so with a valid signature this is usually expected.")
        elif sigs.lacks_trust(sig):
            sev, conf = "high", "medium"
            tail = " The program is not signed by anyone, which makes an innocent explanation less likely."
        else:
            sev, conf = "medium", "low"
            tail = ""
        if threads:
            out.append(Finding(rule="mem.unbacked_thread", title=f"{r.get('name')} is running code that is not backed by any file on disk",
                               severity=sev, confidence=conf, category="memory", collector="memory",
                               description=f"{len(threads)} thread(s) started in memory that was allocated at run time "
                                           "and not loaded from a program file. That is how injected shellcode and "
                                           "reflectively loaded implants run." + tail,
                               evidence=ev, entity=ent, mitre=["T1055", "T1620"], actions=["suspend", "kill"],
                               key_parts=(r.get("path") or r.get("name"),)))
        if regions and not threads:
            out.append(Finding(rule="mem.hidden_module", title=f"{r.get('name')} holds a program image that was mapped by hand",
                               severity=sev, confidence=conf, category="memory", collector="memory",
                               description=f"{len(regions)} executable region(s) begin with a program header but were not "
                                           "loaded by Windows' loader, so they appear in no module list." + tail,
                               evidence=ev, entity=ent, mitre=["T1055.001", "T1620"], actions=["suspend", "kill"],
                               key_parts=(r.get("path") or r.get("name"),)))
    return out
