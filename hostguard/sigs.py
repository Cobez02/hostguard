"""Authenticode verdicts for files, with a cache.

Windows' own verifier does the work (Get-AuthenticodeSignature: embedded signatures and catalog
signatures). It costs about 0.1 s per file the first time, so results are cached by path, size
and modification time. The cache lives in the state folder, which the logged-on user can write
to, so a deep scan ignores it.
"""

from __future__ import annotations

import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor

from . import util

BATCH = 150
WORKERS = 3

_CN_RE = re.compile(r'CN=(?:"([^"]+)"|([^,]+))')
_O_RE = re.compile(r'(?:^|,\s*)O=(?:"([^"]+)"|([^,]+))')

MISSING = {"status": "Missing", "signer": "", "issuer": "", "is_os": False}


def signer_name(subject: str) -> str:
    m = _CN_RE.search(subject or "")
    return (m.group(1) or m.group(2)).strip() if m else ""


def signer_org(subject: str) -> str:
    m = _O_RE.search(subject or "")
    return (m.group(1) or m.group(2)).strip() if m else ""


def is_valid(sig: dict | None) -> bool:
    return bool(sig) and sig.get("status") == "Valid"


def is_unsigned(sig: dict | None) -> bool:
    return bool(sig) and sig.get("status") == "NotSigned"


def lacks_trust(sig: dict | None) -> bool:
    """Checked, and either nobody signed it or the signer is not trusted. Unknown is not untrusted:
    a file that could not be read (an app execution alias, a locked file) is left alone."""
    return bool(sig) and sig.get("status") in ("NotSigned", "NotTrusted")


def checked_and_untrusted(sig: dict | None) -> bool:
    """What automatic containment may act on: Windows examined the file and found no valid signature.

    That covers an unsigned program, an untrusted publisher, a file altered after signing, and a
    file of a kind that cannot carry a signature at all (a batch file, a damaged program), which
    Windows reports as UnknownError. It does not cover a file that could not be opened for the
    check, or a check that never ran: unknown is not guilty."""
    return bool(sig) and sig.get("status") in ("NotSigned", "NotTrusted", "HashMismatch", "UnknownError",
                                               "NotSupportedFileFormat", "Incompatible")


def is_tampered(sig: dict | None) -> bool:
    """Signed, but the file no longer matches its signature."""
    return bool(sig) and sig.get("status") == "HashMismatch"


def is_microsoft(sig: dict | None) -> bool:
    if not is_valid(sig):
        return False
    return bool(sig.get("is_os")) or signer_name(sig.get("signer", "")).lower().startswith("microsoft")


def describe(sig: dict | None) -> str:
    if not sig:
        return "not checked"
    if sig["status"] == "Valid":
        return f"signed by {signer_name(sig.get('signer', '')) or 'unknown'}"
    return {"NotSigned": "not signed", "HashMismatch": "signature does not match the file (tampered)",
            "NotTrusted": "signed by an untrusted publisher", "Missing": "file not found",
            "Unreadable": "could not be read"}.get(sig["status"], sig["status"])


def _run_batch(batch: list[str]) -> list[dict]:
    fd, tmp = tempfile.mkstemp(prefix="hg-sig-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(batch))
        return util.as_list(util.run_ps("signatures", {"InputFile": tmp}, timeout=60 + len(batch) * 3))
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def check(store, file_paths, use_cache: bool = True, log=None) -> dict[str, dict]:
    """{lower-cased path: {status, signer, issuer, is_os}} for every path given."""
    result: dict[str, dict] = {}
    todo: list[tuple[str, int, float]] = []
    seen: set[str] = set()
    for raw in file_paths:
        if not raw:
            continue
        p = util.clean_path(raw)
        key = p.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            st = os.stat(p)
        except OSError:
            result[key] = dict(MISSING)
            continue
        if not os.path.isfile(p):
            result[key] = dict(MISSING)
            continue
        cached = store.sig_get(p, st.st_size, st.st_mtime) if (use_cache and store is not None) else None
        if cached:
            result[key] = cached
        else:
            todo.append((p, st.st_size, st.st_mtime))
    if not todo:
        return result
    if log:
        log(f"checking {len(todo)} signatures ({len(result)} cached)")
    batches = [todo[i:i + BATCH] for i in range(0, len(todo), BATCH)]
    meta = {p.lower(): (p, size, mtime) for p, size, mtime in todo}

    def work(batch):
        try:
            return _run_batch([p for p, _, _ in batch])
        except util.CollectError as e:
            if log:
                log(f"signature batch failed: {e}")
            return []

    with ThreadPoolExecutor(max_workers=min(WORKERS, len(batches))) as pool:
        for rows in pool.map(work, batches):
            for row in rows:
                if not isinstance(row, dict) or not row.get("path"):
                    continue
                key = row["path"].lower()
                sig = {"status": row.get("status") or "UnknownError", "signer": row.get("signer") or "",
                       "issuer": row.get("issuer") or "", "is_os": bool(row.get("is_os"))}
                result[key] = sig
                if store is not None and key in meta and sig["status"] != "Unreadable":
                    p, size, mtime = meta[key]
                    store.sig_put(p, size, mtime, sig)
    for key in meta:
        result.setdefault(key, {"status": "Unreadable", "signer": "", "issuer": "", "is_os": False})
    return result


def lookup(sigs: dict[str, dict], path: str | None) -> dict | None:
    if not path:
        return None
    return sigs.get(util.clean_path(path).lower())
