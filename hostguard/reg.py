"""Read-only registry helpers. Every call returns an empty result when a key is missing or unreadable."""

from __future__ import annotations

import os

if os.name == "nt":
    import winreg
    HKLM, HKCU, HKU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER, winreg.HKEY_USERS
    V64, V32 = winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY
else:  # pragma: no cover  (lets the rule code import on other systems)
    winreg = None
    HKLM, HKCU, HKU, V64, V32 = "HKLM", "HKCU", "HKU", 0, 0

ROOT_NAMES = {HKLM: "HKLM", HKCU: "HKCU", HKU: "HKU"}


def _open(root, path: str, view: int = 0):
    return winreg.OpenKey(root, path, 0, winreg.KEY_READ | (view or V64))


def values(root, path: str, view: int = 0) -> dict[str, object]:
    """{value name: data} for one key. The default value is under the name ''."""
    out: dict[str, object] = {}
    if winreg is None:
        return out
    try:
        with _open(root, path, view) as k:
            i = 0
            while True:
                try:
                    name, data, _typ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = data
                i += 1
    except OSError:
        pass
    return out


def get(root, path: str, name: str, view: int = 0, default=None):
    if winreg is None:
        return default
    try:
        with _open(root, path, view) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def subkeys(root, path: str, view: int = 0) -> list[str]:
    out: list[str] = []
    if winreg is None:
        return out
    try:
        with _open(root, path, view) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def exists(root, path: str, view: int = 0) -> bool:
    if winreg is None:
        return False
    try:
        with _open(root, path, view):
            return True
    except OSError:
        return False


def modified(root, path: str, view: int = 0) -> float | None:
    """When the key was last written, as epoch seconds."""
    if winreg is None:
        return None
    try:
        with _open(root, path, view) as k:
            ticks = winreg.QueryInfoKey(k)[2]
    except OSError:
        return None
    return (ticks - 116444736000000000) / 1e7 if ticks else None


def text(value) -> str:
    """Registry data as one string (REG_MULTI_SZ joined with ' | ', bytes shown as hex)."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " | ".join(str(v) for v in value if v)
    if isinstance(value, bytes):
        return value[:64].hex()
    return str(value)
