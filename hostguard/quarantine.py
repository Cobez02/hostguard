"""The quarantine vault: files are moved here in a form that cannot run, and can be put back.

Each item is two files in the state folder: <id>.hgq holds the bytes XOR-ed with a per-item key
(so the content is inert and matches no signature), <id>.json records where it came from. Nothing
is ever deleted except by an explicit delete of that item.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import time
from pathlib import Path

from . import paths, util, winapi

_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
CHUNK = 1 << 20
MAX_BYTES = 2 << 30


def vault() -> Path:
    return paths.sub("quarantine")


def _table(key: int) -> bytes:
    return bytes(b ^ key for b in range(256))


def _meta_path(item_id: str) -> Path:
    if not _ID.match(item_id or ""):
        raise ValueError("not a quarantine id")
    return vault() / f"{item_id}.json"


def _load(item_id: str) -> dict:
    with open(_meta_path(item_id), "r", encoding="utf-8") as f:
        return json.load(f)


def put(path: str, finding_id: str | None = None, reason: str = "") -> dict:
    """Move a file into the vault. {ok, id, message}"""
    src = util.clean_path(path)
    try:
        st = os.stat(src)
    except OSError as e:
        return {"ok": False, "message": f"can't read {src}: {e.strerror or e}"}
    if not stat.S_ISREG(st.st_mode):
        return {"ok": False, "message": "only single files can be quarantined"}
    if st.st_size > MAX_BYTES:
        return {"ok": False, "message": "the file is larger than 2 GB"}
    item_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    key = secrets.randbelow(255) + 1
    table = _table(key)
    blob = vault() / f"{item_id}.hgq"
    import hashlib
    sha = hashlib.sha256()
    try:
        with open(src, "rb") as fin, open(blob, "wb") as fout:
            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    break
                sha.update(chunk)
                fout.write(chunk.translate(table))
            fout.flush()
            os.fsync(fout.fileno())
    except OSError as e:
        blob.unlink(missing_ok=True)
        denied = isinstance(e, PermissionError)
        return {"ok": False, "needs_elevation": denied, "message":
                f"can't read {src}: " + ("access denied (it is in use, protected, or Defender is already blocking it)" if denied else str(e.strerror or e))}
    meta = {"id": item_id, "original": src, "size": st.st_size, "sha256": sha.hexdigest(), "when": time.time(), "key": key,
            "mtime": st.st_mtime, "finding_id": finding_id, "reason": reason, "encoding": "xor",
            "motw": winapi.read_zone_identifier(src) if winapi.IS_WINDOWS else None}
    paths.atomic_write(vault() / f"{item_id}.json", json.dumps(meta, indent=2))
    try:
        if not os.access(src, os.W_OK):
            os.chmod(src, stat.S_IWRITE | stat.S_IREAD)
        os.remove(src)
    except OSError as e:
        blob.unlink(missing_ok=True)
        (vault() / f"{item_id}.json").unlink(missing_ok=True)
        return {"ok": False, "needs_elevation": isinstance(e, PermissionError), "message":
                f"copied but could not remove {src} ({e.strerror or e}); it is probably running. Suspend or stop the "
                "process first. Nothing was changed."}
    return {"ok": True, "id": item_id, "sha256": meta["sha256"], "message": f"quarantined {src} as {item_id}"}


def items() -> list[dict]:
    out = []
    for f in sorted(vault().glob("*.json"), reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                m = json.load(fh)
        except (OSError, ValueError):
            continue
        if _ID.match(str(m.get("id", ""))):
            m.pop("key", None)
            out.append(m)
    return out


def restore(item_id: str, overwrite: bool = False) -> dict:
    """Put an item back exactly where it came from."""
    try:
        meta = _load(item_id)
    except (OSError, ValueError) as e:
        return {"ok": False, "message": f"no such quarantine item: {e}"}
    target = meta["original"]
    blob = vault() / f"{item_id}.hgq"
    if not blob.is_file():
        return {"ok": False, "message": "the quarantined data is missing from the vault"}
    if os.path.exists(target) and not overwrite:
        return {"ok": False, "message": f"{target} exists again; restore with overwrite to replace it"}
    staging = str(vault() / f"outgoing-{item_id}.tmp")   # decoded here first: the vault is a real, shared location
    note = ""
    try:
        table = _table(int(meta.get("key") or 0)) if meta.get("encoding", "xor") == "xor" else None
        with open(blob, "rb") as fin, open(staging, "wb") as fout:
            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    break
                fout.write(chunk.translate(table) if table else chunk)
        if os.path.exists(target):
            os.remove(target)
        folder = os.path.dirname(target)
        folder_was_there = os.path.isdir(folder)
        os.makedirs(folder, exist_ok=True)
        shutil.copyfile(staging, target)
        if util.is_redirected(target):
            # An app-sandboxed Python wrote a private copy that nothing else can see. Take it back
            # and have Windows' transfer service put the file in the real folder.
            os.remove(target)
            placed = False
            if folder_was_there and not util.is_redirected(folder):
                rc, _out, err = util.run_cmd([paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                              "-File", str(paths.PS_DIR / "place.ps1"), "-Source", staging, "-Destination", target],
                                             timeout=120)
                placed = rc == 0 and os.path.exists(target) and not util.is_redirected(target)
            if not placed:
                alt_dir = paths.sub("restored") / item_id
                alt_dir.mkdir(parents=True, exist_ok=True)
                alt = str(alt_dir / os.path.basename(target))
                os.replace(staging, alt)
                blob.unlink(missing_ok=True)
                _meta_path(item_id).unlink(missing_ok=True)
                return {"ok": True, "path": alt, "relocated": True, "message":
                        f"restored to {alt}. Its original folder ({folder}) is inside AppData, where this Python (the "
                        "Microsoft Store edition) can only write a private copy, and the folder no longer exists for "
                        "Windows to copy into. Move the file back yourself if you need it there."}
            note = " (placed through Windows' transfer service, because this Python is sandboxed)"
        if meta.get("mtime"):
            os.utime(target, (meta["mtime"], meta["mtime"]))
        motw = meta.get("motw")
        if motw and motw.get("zone") is not None:  # keep "this came from the internet" attached
            try:
                with open(target + ":Zone.Identifier", "w", encoding="utf-8") as z:
                    z.write(f"[ZoneTransfer]\r\nZoneId={motw['zone']}\r\n")
                    if motw.get("referrer_url"):
                        z.write(f"ReferrerUrl={motw['referrer_url']}\r\n")
                    if motw.get("host_url"):
                        z.write(f"HostUrl={motw['host_url']}\r\n")
            except OSError:
                pass
    except OSError as e:
        return {"ok": False, "needs_elevation": isinstance(e, PermissionError),
                "message": f"can't write {target}: {e.strerror or e}"}
    finally:
        try:
            os.remove(staging)
        except OSError:
            pass
    blob.unlink(missing_ok=True)
    _meta_path(item_id).unlink(missing_ok=True)
    return {"ok": True, "message": f"restored {target}{note}", "path": target}


def delete(item_id: str) -> dict:
    """Destroy a quarantined item for good."""
    try:
        meta = _load(item_id)
    except (OSError, ValueError) as e:
        return {"ok": False, "message": f"no such quarantine item: {e}"}
    (vault() / f"{item_id}.hgq").unlink(missing_ok=True)
    _meta_path(item_id).unlink(missing_ok=True)
    return {"ok": True, "message": f"permanently deleted the quarantined copy of {meta.get('original')}"}


def adopt(src_moved_to: str, original: str, finding_id: str | None, reason: str) -> dict:
    """Register a file that an elevated helper already moved into the vault as-is."""
    item_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    blob = vault() / f"{item_id}.hgq"
    os.replace(src_moved_to, blob)
    st = os.stat(blob)
    meta = {"id": item_id, "original": original, "size": st.st_size, "sha256": util.sha256_file(blob), "when": time.time(),
            "key": 0, "mtime": st.st_mtime, "finding_id": finding_id, "reason": reason, "encoding": "raw", "motw": None}
    paths.atomic_write(vault() / f"{item_id}.json", json.dumps(meta, indent=2))
    return {"ok": True, "id": item_id, "message": f"quarantined {original} as {item_id}"}
