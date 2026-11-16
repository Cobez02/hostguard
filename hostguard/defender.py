"""Talks to Microsoft Defender's command-line scanner (MpCmdRun.exe).

Used for a second opinion on a specific file, and for the scan and update buttons. A custom scan
with -DisableRemediation only reports: Defender takes no action, writes no event and shows no alert.
"""

from __future__ import annotations

import glob
import os
import re

from . import util

_THREAT = re.compile(r"^\s*Threat\s*:\s*(.+?)\s*$", re.M)


def mpcmdrun() -> str | None:
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    platform = glob.glob(os.path.join(pd, r"Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"))

    def version_key(p: str):
        return [int(x) for x in re.findall(r"\d+", os.path.basename(os.path.dirname(p)))]

    for cand in sorted(platform, key=version_key, reverse=True) + [
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), r"Windows Defender\MpCmdRun.exe")]:
        if os.path.isfile(cand):
            return cand
    return None


def scan_file(path: str, timeout: float = 180) -> dict:
    """Ask Defender about one file without letting it act. {ran, threats, detail}"""
    exe = mpcmdrun()
    if not exe:
        return {"ran": False, "threats": [], "detail": "MpCmdRun.exe not found"}
    if not os.path.exists(path):
        return {"ran": False, "threats": [], "detail": "file not found"}
    rc, out, err = util.run_cmd([exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"], timeout=timeout)
    threats = [t for t in _THREAT.findall(out)]
    counted = re.search(r"found (\d+) threats?", out)
    if not threats and counted and int(counted.group(1)) > 0:
        threats = ["unnamed threat"]
    if (rc not in (0, 2) and not threats) or "Scan finished" not in out:
        return {"ran": False, "threats": [], "detail": util.truncate((out + " " + err).strip(), 300), "rc": rc}
    return {"ran": True, "threats": threats, "detail": "no threats found" if not threats else ", ".join(threats), "rc": rc}


def start_scan(kind: str = "quick", timeout: float = 3600) -> dict:
    """Run a Defender quick (1) or full (2) scan and wait for it. Defender acts on what it finds."""
    exe = mpcmdrun()
    if not exe:
        return {"ok": False, "detail": "MpCmdRun.exe not found"}
    rc, out, err = util.run_cmd([exe, "-Scan", "-ScanType", "2" if kind == "full" else "1"], timeout=timeout)
    return {"ok": rc in (0, 2), "threats_found": rc == 2, "detail": util.truncate((out or err).strip(), 600), "rc": rc}


def update_signatures(timeout: float = 600) -> dict:
    exe = mpcmdrun()
    if not exe:
        return {"ok": False, "detail": "MpCmdRun.exe not found"}
    rc, out, err = util.run_cmd([exe, "-SignatureUpdate"], timeout=timeout)
    return {"ok": rc == 0, "detail": util.truncate((out or err).strip(), 400), "rc": rc}
