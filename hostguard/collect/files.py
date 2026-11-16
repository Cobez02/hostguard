"""Finds and describes the files worth a look: programs, scripts, shortcuts and risky documents in
the folders that downloads, droppers and installers write to."""

from __future__ import annotations

import os
import time
import zipfile

from .. import lnk, paths, pe, util, winapi
from ..detect import content

PE_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".ocx", ".msi"}
SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm", ".ppam", ".potm", ".ppsm"}
OLE_EXT = {".doc", ".xls", ".ppt", ".dot", ".xlt"}
IMAGE_EXT = {".iso", ".img", ".vhd", ".vhdx"}
OTHER_EXT = {".lnk", ".jar", ".chm", ".url", ".appx", ".msix", ".appinstaller", ".one", ".xll", ".wll", ".application"}
# In the riskiest folders a program may be hiding under a harmless extension, so these get their
# first two bytes checked.
SNIFF_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".log", ".dat", ".bin", ".tmp", ".pdf", ".ico", ".db", ".mp3",
             ".mp4", ".csv", ".xml", ".json", ".cfg", ".ini", ""}
HEAD_BYTES = 8 << 20   # how much of each file is read for parsing and signature matching
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages", ".cargo", ".rustup", ".nuget",
             ".gradle", ".m2", "packages", "winsxs", "installer", "assembly", "servicing", "$windows.~bt", ".docker"}


def hot_roots(extra: list[str] | None = None) -> list[tuple[str, int, bool]]:
    """(folder, how deep to go, check file headers for disguised programs)."""
    env = os.environ
    user = env.get("USERPROFILE", "")
    local, roam = env.get("LOCALAPPDATA", ""), env.get("APPDATA", "")
    roots = [
        (os.path.join(user, "Downloads"), 3, True),
        (os.path.join(user, "Desktop"), 2, False),
        (os.path.join(user, "OneDrive", "Desktop"), 2, False),
        (os.path.join(user, "Documents"), 1, False),
        (env.get("TEMP", os.path.join(local, "Temp")), 3, True),
        (os.path.join(paths.WINDIR, "Temp"), 2, True),
        (env.get("PUBLIC", r"C:\Users\Public"), 4, True),
        (env.get("ProgramData", r"C:\ProgramData"), 2, True),
        (roam, 2, False),
        (local, 1, False),
        (os.path.join(roam, r"Microsoft\Windows\Start Menu\Programs\Startup"), 1, True),
        (user, 1, False),
        (os.environ.get("SystemDrive", "C:") + "\\", 1, False),
        (os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "$Recycle.Bin"), 2, False),
    ]
    for d in extra or []:
        roots.append((d, 6, True))
    seen, out = set(), []
    for path, depth, sniff in roots:
        key = os.path.normcase(os.path.abspath(path)) if path else ""
        if key and key not in seen and os.path.isdir(path):
            seen.add(key)
            out.append((path, depth, sniff))
    return out


def risky_folders(extra: list[str] | None = None) -> list[str]:
    """The folders worth a full signature pass with an add-on scanner: where downloads and droppers land."""
    env = os.environ
    user = env.get("USERPROFILE", "")
    cands = [os.path.join(user, "Downloads"), os.path.join(user, "Desktop"), os.path.join(user, "OneDrive", "Desktop"),
             env.get("TEMP", ""), env.get("PUBLIC", r"C:\Users\Public"),
             os.path.join(env.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")] + list(extra or [])
    seen, out = set(), []
    for c in cands:
        key = os.path.normcase(c)
        if c and key not in seen and os.path.isdir(c):
            seen.add(key)
            out.append(c)
    return out


def full_roots(extra: list[str] | None = None) -> list[tuple[str, int, bool]]:
    env = os.environ
    roots = [(env.get("USERPROFILE", ""), 9, False), (env.get("PUBLIC", r"C:\Users\Public"), 9, True),
             (env.get("ProgramData", r"C:\ProgramData"), 6, True), (os.path.join(paths.WINDIR, "Temp"), 4, True)]
    for d in extra or []:
        roots.append((d, 9, True))
    return [(p, d, s) for p, d, s in roots if p and os.path.isdir(p)] + [r for r in hot_roots() if r[0].endswith(("\\", "$Recycle.Bin"))]


def walk(roots: list[tuple[str, int, bool]], max_files: int, deadline: float | None = None):
    """Yield (path, DirEntry stat, sniff) for candidate files, breadth-limited and bounded."""
    seen_dirs: set[str] = set()
    count = 0
    for root, depth, sniff in roots:
        stack = [(root, 0)]
        while stack:
            folder, level = stack.pop()
            key = os.path.normcase(folder)
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if level + 1 < depth and e.name.lower() not in SKIP_DIRS:
                            stack.append((e.path, level + 1))
                        continue
                    ext = os.path.splitext(e.name)[1].lower()
                    interesting = ext in PE_EXT or ext in SCRIPT_EXT or ext in MACRO_EXT or ext in IMAGE_EXT or ext in OTHER_EXT \
                        or ext in OLE_EXT or (sniff and ext in SNIFF_EXT) or "\u202e" in e.name
                    if not interesting:
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                count += 1
                yield e.path, st, sniff
                if count >= max_files or (deadline and time.time() > deadline):
                    return


def _macro_in_ooxml(path: str) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            return any(n.lower().endswith("vbaproject.bin") for n in z.namelist())
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def describe(path: str, st, sniff: bool, max_bytes: int) -> dict | None:
    """Facts about one file, or None when it turns out not to be interesting."""
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    size = st.st_size
    fact: dict = {"path": path, "name": name, "ext": ext, "size": size, "modified": st.st_mtime,
                  "created": getattr(st, "st_birthtime", None) or st.st_ctime, "zone": util.path_zone(path), "type": "other"}
    head = b""
    wants_body = ext in PE_EXT or ext in SCRIPT_EXT or ext in OLE_EXT or ext in (".lnk", ".url")
    sniff_only = not wants_body and sniff and ext in SNIFF_EXT
    if size and (wants_body or sniff_only):
        try:
            with open(path, "rb") as f:
                head = f.read(256 if sniff_only else min(size, HEAD_BYTES))
                if sniff_only and head[:2] == b"MZ":
                    head += f.read(max(0, min(size, HEAD_BYTES) - len(head)))
        except OSError:
            fact["unreadable"] = True
            head = b""
    is_pe = head[:2] == b"MZ"
    if is_pe:
        fact["type"] = "pe"
        fact["disguised"] = ext not in PE_EXT
        parsed = pe.PE(head, size)
        if parsed.valid:
            fact["pe"] = parsed.summary()
        fact["sha256"] = util.sha256_file(path) if size <= max_bytes else None
        fact["signatures"] = [s.id for s in content.scan(head)]
    elif ext in SCRIPT_EXT:
        fact["type"] = "script"
        if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = head[:400000].decode("utf-16", "replace")
        else:
            text = head[:400000].decode("utf-8", "replace")
        fact["text"] = text
        fact["sha256"] = util.sha256_file(path) if size <= max_bytes else None
        fact["signatures"] = [s.id for s in content.scan(head[:4 << 20])]
    elif ext == ".lnk":
        fact["type"] = "lnk"
        fact["lnk"] = lnk.parse_bytes(head) or {}
    elif ext == ".url":
        fact["type"] = "url"
        fact["text"] = head[:4000].decode("utf-8", "replace")
    elif ext in MACRO_EXT:
        fact["type"] = "office"
        fact["macros"] = _macro_in_ooxml(path)
    elif ext in OLE_EXT:
        fact["type"] = "office"
        fact["macros"] = b"_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T" in head or b"_VBA_PROJECT" in head
        if not fact["macros"]:
            return None
    elif ext in IMAGE_EXT:
        fact["type"] = "disk_image"
    elif ext in OTHER_EXT:
        fact["type"] = ext.lstrip(".")
    elif "\u202e" in name:
        fact["type"] = "other"
    else:
        if head[:4] == content.EICAR[:4] and content.EICAR in head[:200]:
            fact["signatures"] = ["eicar"]
            fact["type"] = "other"
        else:
            return None  # sniffed and found to be what its extension says
    motw = winapi.read_zone_identifier(path) if winapi.IS_WINDOWS else None
    if motw:
        fact["motw"] = motw
    if fact["type"] in ("disk_image", "office", "jar", "chm", "one", "appx", "msix", "appinstaller", "application") and not motw \
            and "\u202e" not in name:
        if fact["type"] != "office" or not fact.get("macros"):
            return None  # only interesting when it came from the internet
    return fact


def collect(profile: str = "quick", cfg: dict | None = None, log=None, budget_s: float = 240) -> dict:
    cfg = cfg or {}
    scan_cfg = cfg.get("scan") or {}
    max_bytes = int(scan_cfg.get("max_file_mb", 64)) << 20
    max_files = int(scan_cfg.get("max_files", 20000))
    extra = list(scan_cfg.get("extra_dirs") or [])
    roots = full_roots(extra) if profile in ("full", "deep") else hot_roots(extra)
    deadline = time.time() + (budget_s * (4 if profile in ("full", "deep") else 1))
    files, seen, considered = [], set(), 0
    for path, st, sniff in walk(roots, max_files, deadline):
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        considered += 1
        try:
            fact = describe(path, st, sniff, max_bytes)
        except (OSError, ValueError):
            continue
        if fact:
            files.append(fact)
    truncated = considered >= max_files or time.time() > deadline
    if log:
        log(f"files: looked at {considered}, kept {len(files)}" + (" (stopped at the limit)" if truncated else ""))
    return {"files": files, "considered": considered, "truncated": truncated, "roots": [r[0] for r in roots]}
