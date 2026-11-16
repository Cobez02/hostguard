"""Shared helpers: running PowerShell collectors, hashing, path and command-line parsing."""

from __future__ import annotations

import base64
import collections
import datetime as _dt
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import paths

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class CollectError(RuntimeError):
    """A collector could not get its data (the scan records it as a coverage gap and continues)."""


# ------------------------------------------------------------------ subprocess

def child_env() -> dict[str, str]:
    """The environment for the programs HostGuard starts: this one's, minus PSModulePath.

    A PowerShell 7 terminal exports its own module folders in that variable. Windows PowerShell 5.1,
    which HostGuard's helper scripts run in, then picks up PowerShell 7's copies of its built-in
    modules and cannot load them, so every signature check would fail. Without the variable it
    works out its own defaults."""
    return {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}


def run_cmd(argv: list[str], timeout: float = 60, input_text: str | None = None) -> tuple[int, str, str]:
    """Run a program without a console window. Never raises on a non-zero exit."""
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout, creationflags=NO_WINDOW, env=child_env(),
                           input=input_text.encode("utf-8") if input_text is not None else None,
                           stdin=subprocess.DEVNULL if input_text is None else None)
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout:.0f}s"
    except OSError as e:
        return 127, "", str(e)
    return r.returncode, _decode(r.stdout), _decode(r.stderr)


def _decode(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("mbcs" if os.name == "nt" else "latin-1", "replace")


def run_ps(what: str, args: dict | None = None, timeout: float = 180):
    """Run one section of ps/collect.ps1 and return its parsed JSON output."""
    script = paths.PS_DIR / "collect.ps1"
    argv = [paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(script), "-What", what]
    for k, v in (args or {}).items():
        argv += [f"-{k}", str(v)]
    rc, out, err = run_cmd(argv, timeout=timeout)
    if rc == 124:
        raise CollectError(f"{what}: PowerShell {err}")
    text = out.strip()
    if not text:
        if rc != 0:
            raise CollectError(f"{what}: PowerShell exited {rc}: {err.strip()[:300]}")
        return None
    try:
        return json.loads(text)
    except ValueError:
        # A stray warning line before the JSON: take the last line that parses.
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line[:1] in "[{":
                try:
                    return json.loads(line)
                except ValueError:
                    continue
        raise CollectError(f"{what}: unreadable PowerShell output: {text[:200]!r}") from None


def as_list(value) -> list:
    """PowerShell 5.1 unwraps one-element arrays and turns empty ones into null."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# ------------------------------------------------------------------ hashing and content

def sha256_file(path: str | os.PathLike, max_bytes: int | None = None) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            left = max_bytes
            while True:
                chunk = f.read(1 << 20 if left is None else min(1 << 20, left))
                if not chunk:
                    break
                h.update(chunk)
                if left is not None:
                    left -= len(chunk)
                    if left <= 0:
                        break
    except OSError:
        return None
    return h.hexdigest()


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0-8). Packed or encrypted data sits above about 7.2."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values())


def truncate(text, limit: int = 400) -> str:
    text = "" if text is None else str(text)
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Edit distance, giving up once it exceeds `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


# ------------------------------------------------------------------ paths

_ENV_PF = [os.environ.get(k, "") for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")]
_PF = sorted({p.lower().rstrip("\\") for p in _ENV_PF if p} | {r"c:\program files", r"c:\program files (x86)"})
_WIN = paths.WINDIR.lower().rstrip("\\")
_USER_RE = re.compile(r"^[a-z]:\\users\\[^\\]+\\(.*)$")

# Zones an unprivileged program can write to. A binary that runs from one was put there without
# administrator rights, which is where most malware on a home PC lives.
USER_WRITABLE = {"temp", "downloads", "desktop", "appdata", "user", "public", "programdata", "recycle",
                 "root", "other", "network"}
HIGH_RISK = {"temp", "downloads", "public", "recycle"}


def clean_path(path: str) -> str:
    p = (path or "").strip().strip('"').replace("/", "\\")
    low = p.lower()
    if low.startswith("\\??\\"):
        p = p[4:]
    elif low.startswith("\\systemroot\\"):
        p = paths.WINDIR + p[11:]
    elif low.startswith(("system32\\", "syswow64\\")):
        p = paths.WINDIR + "\\" + p
    return os.path.expandvars(p)


def path_zone(path: str) -> str:
    """Where a path lives, in terms of who can write there."""
    p = clean_path(path).lower()
    if not p:
        return "other"
    if p.startswith("\\\\"):
        return "network"
    if p.startswith(_WIN + "\\temp\\"):
        return "temp"
    if p.startswith(_WIN + "\\") or p == _WIN:
        return "windows"
    if any(p.startswith(pf + "\\") for pf in _PF):
        return "program_files"
    if "\\$recycle.bin\\" in p:
        return "recycle"
    if re.match(r"^[a-z]:\\users\\public\\", p):
        return "public"
    if re.match(r"^[a-z]:\\programdata\\", p):
        return "programdata"
    m = _USER_RE.match(p)
    if m:
        rest = m.group(1)
        if rest.startswith("appdata\\local\\temp\\"):
            return "temp"
        if rest.startswith("downloads\\"):
            return "downloads"
        if rest.startswith(("desktop\\", "onedrive\\desktop\\")):
            return "desktop"
        if rest.startswith("appdata\\"):
            return "appdata"
        return "user"
    if re.match(r"^[a-z]:\\[^\\]+$", p):
        return "root"
    return "other"


def is_redirected(path: str) -> bool:
    """True when an existing path physically lives in an app sandbox's private copy.

    Windows gives a packaged program (a Python from the Microsoft Store is one) its own copy of any
    new file under AppData, kept in a LocalCache folder below AppData's Packages folder. Resolving
    the path shows that. Any other difference between a path and its resolved form (a short 8.3
    name, a link, a mapped drive) is not redirection, and must not be treated as one."""
    try:
        real = os.path.normcase(os.path.realpath(path))
    except OSError:
        return False
    cache, packages = os.sep + "localcache" + os.sep, os.sep + "packages" + os.sep
    return cache in real and packages in real and cache not in os.path.normcase(os.path.abspath(path))


def is_under(path: str, roots: list[str]) -> bool:
    p = clean_path(path).lower().rstrip("\\") + "\\"
    for r in roots:
        r = clean_path(r).lower().rstrip("\\")
        if r and p.startswith(r + "\\"):
            return True
    return False


_IMAGE_RE = re.compile(r"^(.+?\.(?:exe|com|bat|cmd|scr|pif|dll|sys|msi|vbs|vbe|js|jse|wsf|ps1|cpl|hta))(?=\s|,|$)",
                       re.I)


def split_command(cmd: str) -> tuple[str, str]:
    """(program, arguments) from an autorun, task or service command line."""
    s = clean_path(cmd) if cmd and not cmd.strip().startswith('"') else os.path.expandvars((cmd or "").strip())
    if not s:
        return "", ""
    if s.startswith('"\\"'):  # a value stored with its quotes escaped: "\"C:\x\app.exe\" --flag"
        s = s[1:].replace('\\"', '"')
        if s.endswith('"') and s.count('"') % 2:
            s = s[:-1]
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return clean_path(s[1:end]), s[end + 1:].strip()
        return clean_path(s[1:]), ""
    m = _IMAGE_RE.match(s)
    if m:
        return m.group(1), s[m.end():].strip()
    parts = s.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def resolve_image(image: str) -> str:
    """Full path for a bare program name the way Windows would find it (System32 first)."""
    image = clean_path(image)
    if not image or "\\" in image or ":" in image:
        return image
    names = [image] if os.path.splitext(image)[1] else [image + ".exe", image + ".com", image + ".bat", image + ".cmd"]
    for folder in (paths.SYSTEM32, os.path.join(paths.WINDIR, "SysWOW64"), paths.WINDIR):
        for n in names:
            cand = os.path.join(folder, n)
            if os.path.isfile(cand):
                return cand
    found = shutil.which(image)
    return found or image


def basename(path: str) -> str:
    return clean_path(path).replace("/", "\\").rsplit("\\", 1)[-1].lower()


# ------------------------------------------------------------------ command lines

_ENC_FLAG_RE = re.compile(r"(?i)(?:^|\s)[-/]([a-z]+)\s+['\"]?([A-Za-z0-9+/]{20,}={0,2})")


def decode_encoded_command(cmdline: str) -> str | None:
    """The script hidden in a PowerShell -EncodedCommand argument, if there is one."""
    for m in _ENC_FLAG_RE.finditer(cmdline or ""):
        flag = m.group(1).lower()
        if not ("encodedcommand".startswith(flag) or flag == "ec"):
            continue
        blob = m.group(2)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (ValueError, TypeError):
            continue
        for enc in ("utf-16-le", "utf-8"):
            try:
                text = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
            if text and printable / len(text) > 0.85:
                return text
    return None


# ------------------------------------------------------------------ network

def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global


def is_loopback(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_loopback


_MESH = ipaddress.ip_network("100.64.0.0/10")


def is_mesh_vpn_ip(ip: str) -> bool:
    """Carrier-grade NAT space, which Tailscale and similar overlay VPNs assign to devices."""
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return a.version == 4 and a in _MESH


def is_wildcard_addr(ip: str) -> bool:
    return ip in ("0.0.0.0", "::", "")


# ------------------------------------------------------------------ time

def iso(ts: float | None) -> str:
    if not ts:
        return ""
    return _dt.datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def parse_time(value) -> float | None:
    """Epoch seconds from the date formats Windows tools emit (ISO 8601, /Date(ms)/)."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    m = re.match(r"^/Date\((-?\d+)", s)
    if m:
        return int(m.group(1)) / 1000.0
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # .NET writes 7 fractional digits
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        d = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.astimezone()
    return d.timestamp()


def age_days(ts: float | None, now: float | None = None) -> float | None:
    if not ts:
        return None
    import time
    return ((now or time.time()) - ts) / 86400.0


def write_json(path: Path, obj) -> None:
    paths.atomic_write(path, json.dumps(obj, indent=2, default=str))
