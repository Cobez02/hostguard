"""Where HostGuard keeps its state, and its configuration file."""

from __future__ import annotations

import copy
import json
import os
import sys
import threading
from pathlib import Path

APP = "HostGuard"
PKG_DIR = Path(__file__).resolve().parent
ROOT = PKG_DIR.parent
PS_DIR = PKG_DIR / "ps"
LAUNCHER = PKG_DIR / "launch.py"
# The folder that holds HostGuard's own code. From a source checkout that is the whole folder
# (run.py sits next to the package). Installed with pip it is the package alone, because its
# parent is then site-packages, which every other installed program shares.
OWN_DIR = ROOT if (ROOT / "run.py").is_file() else PKG_DIR

_SYSROOT = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
POWERSHELL = str(Path(_SYSROOT) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
SYSTEM32 = str(Path(_SYSROOT) / "System32")
WINDIR = str(Path(_SYSROOT))

DEFAULTS: dict = {
    "containment": {
        # off: report only.  ask: queue actions for your approval.  auto: act on its own (reversible actions only).
        "mode": "ask",
        "auto_min_severity": "critical",
        "auto_min_confidence": "high",
        "process_action": "suspend",        # suspend | kill | none
        "file_action": "quarantine",        # quarantine | none
        "autorun_action": "disable",        # disable | none
        "isolate_on_critical": False,       # cut the network when a critical finding is auto-contained
        "max_auto_actions_per_hour": 10,
        "agent_can_escalate": False,        # may an LLM verdict push a finding into automatic containment
    },
    "scan": {
        "lookback_days": 7,
        "max_file_mb": 64,
        "max_files": 20000,
        "extra_dirs": [],
        "defender_ondemand": True,
    },
    # Folders you declare as yours (security tooling, lab samples). Findings inside are kept but
    # downgraded and tagged, and automatic containment never touches them.
    "trusted": {"paths": []},
    "agent": {
        "endpoint": "http://127.0.0.1:11434/v1",
        "model": "",
        "api_key": "",
        "max_steps": 14,
        "timeout_s": 600,
        "keep_alive": "5m",
        "online_lookups": False,
    },
    "monitor": {
        "process_interval_s": 2,
        "network_interval_s": 15,
        "events_interval_s": 30,
        "defender_interval_s": 60,
        "persistence_interval_s": 300,
        "files_interval_s": 20,
        "notify": True,
        "watch_dirs": [],
    },
    "intel": {"enabled": False},
}

_lock = threading.RLock()


def home() -> Path:
    """The state folder: ~/.hostguard. HOSTGUARD_HOME overrides it (the tests use that).

    It is deliberately NOT under AppData. A Python from the Microsoft Store runs in an app sandbox
    that gives it a private copy of anything new it creates there, so the dashboard, the command
    line and the elevated helper could each end up looking at a different folder.
    """
    env = os.environ.get("HOSTGUARD_HOME")
    p = Path(env) if env else Path.home() / ".hostguard"
    p.mkdir(parents=True, exist_ok=True)
    return p


def python_is_sandboxed() -> bool:
    """True for a Microsoft Store Python, whose new files under AppData are private to it."""
    return (os.sep + "windowsapps" + os.sep) in (sys.executable + "|" + sys.base_prefix).lower()


def background_command(*args: str) -> list[str]:
    """The command line for one of HostGuard's own windowless processes (the monitor, the dashboard).

    It names the launcher file by its full path, never `-m hostguard`: scans recognise HostGuard's
    own processes and its startup entry by that path, and it reads the same from a source checkout
    and from an installed copy."""
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return [pyw if os.path.isfile(pyw) else exe, str(LAUNCHER), *args]


def sub(name: str) -> Path:
    p = home() / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_path() -> Path:
    return home() / "config.json"


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    """Defaults overlaid with config.json. A broken file falls back to defaults (and is left alone)."""
    with _lock:
        try:
            raw = json.loads(config_path().read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raw = {}
        except (OSError, ValueError):
            raw = {}
        return _merge(DEFAULTS, raw)


def atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def save_config(cfg: dict) -> None:
    with _lock:
        atomic_write(config_path(), json.dumps(cfg, indent=2, sort_keys=True))


_ALLOWED = {
    ("containment", "mode"): {"off", "ask", "auto"},
    ("containment", "auto_min_severity"): {"medium", "high", "critical"},
    ("containment", "auto_min_confidence"): {"medium", "high"},
    ("containment", "process_action"): {"suspend", "kill", "none"},
    ("containment", "file_action"): {"quarantine", "none"},
    ("containment", "autorun_action"): {"disable", "none"},
}


def set_value(dotted: str, value) -> dict:
    """Set one setting by dotted name (containment.mode), type-checked against the defaults."""
    keys = dotted.split(".")
    with _lock:
        cfg = load_config()
        node, dnode = cfg, DEFAULTS
        for k in keys[:-1]:
            if not isinstance(dnode.get(k), dict):
                raise ValueError(f"unknown setting: {dotted}")
            node, dnode = node[k], dnode[k]
        leaf = keys[-1]
        if leaf not in dnode:
            raise ValueError(f"unknown setting: {dotted}")
        want = dnode[leaf]
        if isinstance(want, dict):
            raise ValueError(f"{dotted} is a group of settings; name one of: {', '.join(dotted + '.' + k for k in want)}")
        if isinstance(want, bool):
            if isinstance(value, str):
                if value.lower() not in ("true", "false", "on", "off", "1", "0"):
                    raise ValueError(f"{dotted} must be true or false")
                value = value.lower() in ("true", "on", "1")
            elif not isinstance(value, bool):
                raise ValueError(f"{dotted} must be true or false")
        elif isinstance(want, int):
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{dotted} must be a whole number") from None
            if value < 0:
                raise ValueError(f"{dotted} can't be negative")
        elif isinstance(want, list):
            if isinstance(value, str):
                value = [v.strip() for v in value.split(";") if v.strip()]
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"{dotted} must be a list of text values")
        elif isinstance(want, str):
            if not isinstance(value, str):
                raise ValueError(f"{dotted} must be text")
        allowed = _ALLOWED.get(tuple(keys))
        if allowed and value not in allowed:
            raise ValueError(f"{dotted} must be one of: {', '.join(sorted(allowed))}")
        node[leaf] = value
        save_config(cfg)
        return cfg
