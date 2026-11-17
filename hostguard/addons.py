"""Download and install the optional open-source add-ons, when and only when you ask for one.

HostGuard fetches nothing by itself. This module is its one way out to the internet for files,
and it is deliberately narrow:

  * It can fetch only the files pinned below: fixed release URLs on github.com, each with the size
    and SHA-256 that the project's own release page published on the day it was pinned.
  * A download is kept only if its size and hash match the pin. A mismatch means the release was
    changed after it was pinned, and the file is thrown away before anything is unpacked.
  * Redirects are followed only to GitHub's own download hosts, over HTTPS.
  * Archives are unpacked member by member. Every path must stay inside the add-on's folder, and
    there are limits on how many files and how many bytes an archive may hold.
  * Nothing downloaded is run here. The next scan starts the tool exactly as it would start one
    you had put in the folder by hand.

Updating a pin means reading the new release's file name, size and SHA-256 from its release page
(GitHub shows the digest next to each file) and writing them here. Until then HostGuard keeps
installing the release it knows.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from . import __version__, components, util

ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
MAX_FILES = 30000                       # Hayabusa ships several thousand rule files
MAX_UNPACKED = 600 * 1024 * 1024
CHUNK = 1 << 16
MANIFEST = "hostguard-addon.json"
PINNED_ON = "2026-11-16"
_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}

# kind: "zip" unpacks the whole archive, "rules" keeps only YARA rule files (flattened into one
# folder), "file" stores the download itself. "into" is a folder below the add-on's own folder.
PINS: dict[str, dict] = {
    "yara": {"version": "4.6.0, with the YARA Forge core rules of 2026-11-15", "files": [
        {"name": "yara-4.6.0-2443-win64.zip", "kind": "zip", "into": "", "size": 2238893,
         "url": "https://github.com/VirusTotal/yara/releases/download/v4.6.0/yara-4.6.0-2443-win64.zip",
         "sha256": "5e7124f173ed442458429ac0f79a4db2c024cc183c595737d477a7575d81e6dc"},
        {"name": "yara-forge-rules-core.zip", "kind": "rules", "into": "rules", "size": 1724787,
         "url": "https://github.com/YARAHQ/yara-forge/releases/download/20261115/yara-forge-rules-core.zip",
         "sha256": "d8cbfc7940c688bd890f941c323f51940c54b46bb2a78143b55d312bab7581c6"},
    ]},
    "hollows_hunter": {"version": "0.4.1.1", "files": [
        {"name": "hollows_hunter64.exe", "kind": "file", "into": "", "size": 1260032,
         "url": "https://github.com/hasherezade/hollows_hunter/releases/download/v0.4.1.1/hollows_hunter64.exe",
         "sha256": "56a58a8bbf2cec9a5c7c68129e8863af6181fb51dfc25226f1a756aba66b4707"},
    ]},
    # "program" is the executable inside the archive. Hayabusa runs elevated, and ps/elevated.ps1 runs
    # an unsigned copy only if it is exactly this file, so the two values must be kept together.
    "hayabusa": {"version": "4.4.0", "program": "b73e41ca75f1f79348550242cd02a9d37207240cd72b1256549ee704969bf403", "files": [
        {"name": "hayabusa-4.4.0-win-x64.zip", "kind": "zip", "into": "", "size": 16472955,
         "url": "https://github.com/Yamato-Security/hayabusa/releases/download/v4.4.0/hayabusa-4.4.0-win-x64.zip",
         "sha256": "ec2670062531723856e278b058473512884e8c5b8d2d1ad60e48c0c868fbf339"},
    ]},
}


class Refused(Exception):
    """A download or an archive that does not meet the rules above. Nothing is installed."""


def check_url(url: str) -> str:
    """The URL, if it is HTTPS on one of GitHub's download hosts. Anything else is refused."""
    try:
        u = urllib.parse.urlsplit(url)
        host, port = (u.hostname or "").lower(), u.port
    except ValueError:
        raise Refused("refusing a malformed download address") from None
    if u.scheme != "https" or host not in ALLOWED_HOSTS or port not in (None, 443) or u.username or u.password:
        raise Refused(f"refusing to download from {u.scheme}://{host or '?'}: only GitHub's own download hosts over HTTPS are allowed")
    return url


class _OnlyGitHub(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str):
    """Open a pinned URL. The system's proxy settings apply; certificates are verified as usual."""
    opener = urllib.request.build_opener(_OnlyGitHub)
    request = urllib.request.Request(check_url(url), headers={"User-Agent": f"hostguard/{__version__}", "Accept": "application/octet-stream"})
    return opener.open(request, timeout=60)


def _size(n: int) -> str:
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{max(1, round(n / 1024))} KB"


def _source(url: str) -> str:
    parts = urllib.parse.urlsplit(url).path.strip("/").split("/")
    return "github.com/" + "/".join(parts[:2])


def plan(addon_id: str, pins: dict | None = None) -> dict | None:
    """What installing this add-on would download, for the confirmation the user sees first."""
    pin = (PINS if pins is None else pins).get(addon_id)
    if not pin:
        return None
    return {"version": pin["version"], "bytes": sum(f["size"] for f in pin["files"]), "pinned_on": PINNED_ON,
            "files": [{"name": f["name"], "size": f["size"], "size_text": _size(f["size"]), "source": _source(f["url"]), "url": f["url"],
                       "sha256": f["sha256"]} for f in pin["files"]]}


def installed_info(addon_id: str) -> dict | None:
    """What HostGuard itself installed in this add-on's folder, if it did."""
    entry = next((c for c in components.CATALOG if c["id"] == addon_id), None)
    if not entry:
        return None
    try:
        with open(os.path.join(components.tools_dir(), entry["folder"], MANIFEST), encoding="utf-8") as f:
            info = json.load(f)
    except (OSError, ValueError):
        return None
    return info if isinstance(info, dict) else None


def _fetch(file: dict, dest: str, open_url) -> None:
    """Download one pinned file to dest. It stays there only if its size and SHA-256 match the pin."""
    digest, got = hashlib.sha256(), 0
    try:
        with open_url(file["url"]) as response, open(dest, "wb") as out:
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                got += len(chunk)
                if got > file["size"]:
                    raise Refused(f"{file['name']} is larger than the {file['size']} bytes of the pinned release")
                digest.update(chunk)
                out.write(chunk)
        if got != file["size"]:
            raise Refused(f"{file['name']} arrived as {got} bytes; the pinned release has {file['size']}")
        if digest.hexdigest() != file["sha256"]:
            raise Refused(f"{file['name']} does not match its pinned SHA-256, so it is not the file that was checked on {PINNED_ON}")
    except BaseException:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise


def _member_path(name: str) -> str | None:
    """Where an archive member goes, relative to the target folder. None for a folder entry."""
    unified = name.replace("\\", "/")
    if unified.endswith("/"):
        return None
    parts = [p for p in unified.split("/") if p not in ("", ".")]
    bad = (not parts or unified.startswith("/")
           or any(p == ".." or ":" in p or p.rstrip(". ") != p or p.split(".")[0].lower() in _RESERVED for p in parts))
    if bad:
        raise Refused(f"the archive holds an unsafe path: {name!r}")
    return os.path.join(*parts)


def _unpack(archive: str, target: str, only_rules: bool) -> int:
    """Unpack into target without trusting the archive. Returns how many files were written."""
    written = 0
    root = os.path.abspath(target)
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        if len(members) > MAX_FILES:
            raise Refused(f"the archive holds {len(members)} entries; more than {MAX_FILES} is refused")
        if sum(m.file_size for m in members) > MAX_UNPACKED:
            raise Refused("the archive would unpack to more than 600 MB")
        for member in members:
            rel = _member_path(member.filename)
            if rel is None:
                continue
            if only_rules:
                if not rel.lower().endswith((".yar", ".yara")):
                    continue
                rel = os.path.basename(rel)
            out = os.path.abspath(os.path.join(root, rel))
            if not util.is_under(out, [root]):
                raise Refused(f"the archive holds a path that leaves its folder: {member.filename!r}")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with z.open(member) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, CHUNK)
            written += 1
    if not written:
        raise Refused("the archive held none of the expected files")
    return written


def install(addon_id: str, log=None, open_url=None, pins: dict | None = None) -> dict:
    """Download, verify and unpack one add-on. Files you already keep in its folder are left alone."""
    pins = PINS if pins is None else pins
    entry = next((c for c in components.CATALOG if c["id"] == addon_id), None)
    pin = pins.get(addon_id)
    if not entry or not pin:
        return {"ok": False, "message": f"there is no downloadable add-on called {addon_id!r}"}
    log = log or (lambda _line: None)
    tools = components.tools_dir()
    final = os.path.join(tools, entry["folder"])
    staging = os.path.join(tools, f".incoming-{entry['folder']}-{os.getpid()}")
    fresh = os.path.join(staging, "new")
    shutil.rmtree(staging, ignore_errors=True)
    try:
        os.makedirs(fresh)
        for f in pin["files"]:
            log(f"Downloading {f['name']} ({_size(f['size'])}) from {_source(f['url'])}")
            blob = os.path.join(staging, os.path.basename(f["name"]))
            _fetch(f, blob, open_url or _open)
            log(f"{f['name']}: size and SHA-256 match the pinned release")
            target = os.path.join(fresh, f["into"]) if f["into"] else fresh
            os.makedirs(target, exist_ok=True)
            if f["kind"] == "file":
                os.replace(blob, os.path.join(target, os.path.basename(f["name"])))
            else:
                count = _unpack(blob, target, only_rules=f["kind"] == "rules")
                log(f"{f['name']}: unpacked {count} file(s)")
                os.remove(blob)
        with open(os.path.join(fresh, MANIFEST), "w", encoding="utf-8") as out:
            json.dump({"addon": addon_id, "version": pin["version"], "installed": time.time(), "by": f"hostguard {__version__}",
                       "files": [{k: f[k] for k in ("name", "url", "sha256", "size")} for f in pin["files"]]}, out, indent=1)
        shutil.copytree(fresh, final, dirs_exist_ok=True)      # merge: nothing already in the folder is deleted
    except Refused as e:
        return {"ok": False, "message": f"nothing was installed: {e}"}
    except urllib.error.HTTPError as e:
        why = "the pinned file is no longer published there" if e.code == 404 else f"GitHub answered {e.code}"
        return {"ok": False, "message": f"nothing was installed: {why}. You can still place the tool by hand."}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"ok": False, "message": f"nothing was installed: the download failed ({getattr(e, 'reason', e)}). Is this PC online?"}
    except zipfile.BadZipFile:
        return {"ok": False, "message": "nothing was installed: the download is not a readable archive"}
    except OSError as e:
        return {"ok": False, "message": f"nothing was installed: {e}"}
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    row = next((r for r in components.status() if r["id"] == addon_id), None)
    if not row or not row["installed"]:
        return {"ok": False, "message": f"{entry['title']} was unpacked into {final}, but its program is not there now. "
                                        "Microsoft Defender may have removed it: look at its Protection history."}
    program = components.find(addon_id)
    if pin.get("program") and program and util.sha256_file(program) != pin["program"]:
        return {"ok": False, "message": f"{entry['title']} was unpacked, but its program is not the one this version of HostGuard "
                                        "expects, so it will not be run with administrator rights."}
    return {"ok": True, "message": f"{entry['title']} {pin['version']} is installed. The next scan uses it.", "path": final}


def remove(addon_id: str) -> dict:
    """Delete an add-on's folder, with everything in it."""
    entry = next((c for c in components.CATALOG if c["id"] == addon_id), None)
    if not entry:
        return {"ok": False, "message": f"there is no add-on called {addon_id!r}"}
    tools = os.path.abspath(components.tools_dir())
    folder = os.path.abspath(os.path.join(tools, entry["folder"]))
    if os.path.dirname(folder) != tools:
        return {"ok": False, "message": "refusing to remove anything outside the tools folder"}
    if not os.path.isdir(folder):
        return {"ok": True, "message": f"{entry['title']} is not installed"}
    try:
        shutil.rmtree(folder)
    except OSError as e:
        return {"ok": False, "message": f"could not remove {folder}: {e}"}
    return {"ok": not os.path.exists(folder), "message": f"{entry['title']} removed"}
