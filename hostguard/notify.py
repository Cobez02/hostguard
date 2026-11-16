"""Windows notifications for new findings, rate-limited so a noisy hour cannot bury the screen."""

from __future__ import annotations

import json
import os
import tempfile
import time

from . import paths, util

MAX_PER_10_MIN = 6
_sent: list[float] = []


def toast(title: str, text: str) -> bool:
    """Show a notification. False when it was rate-limited or could not be shown."""
    now = time.time()
    _sent[:] = [t for t in _sent if now - t < 600]
    if len(_sent) >= MAX_PER_10_MIN:
        return False
    fd, tmp = tempfile.mkstemp(prefix="hg-toast-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"title": util.truncate(title, 120), "text": util.truncate(text, 300)}, f)
    rc, _out, _err = util.run_cmd([paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                   "-File", str(paths.PS_DIR / "toast.ps1"), "-Json", tmp], timeout=30)
    if rc == 0:
        _sent.append(now)
    else:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return rc == 0


def for_finding(f: dict, acted: str | None = None) -> bool:
    """Announce a finding. Only the rule's own title is shown, never a raw command line."""
    head = {"critical": "HostGuard: critical", "high": "HostGuard: high", "medium": "HostGuard"}.get(f["severity"], "HostGuard")
    body = f["title"] + (f"\n{acted}" if acted else "\nOpen the HostGuard dashboard to review.")
    return toast(head, body)
