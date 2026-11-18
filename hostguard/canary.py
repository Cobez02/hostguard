"""Ransomware canaries: decoy documents in places nothing has a reason to touch.

Ransomware works through the disk and rewrites every document it reaches. A canary is a hidden
folder of decoy documents, with one more hidden decoy beside it, named so that both sort first in
the folder that holds them. A program working through that folder reaches a decoy before a real
file, whether it takes a folder's own files first or goes into its subfolders first. HostGuard
records each decoy's contents, owner and permissions when it places it, and compares them from
then on. Nothing else has a reason to touch one, so a change means something is going through the
disk.

This module places the canaries, takes them away and reports the state they are in. It judges
nothing: detect/canary.py turns the report into findings.

    Read back, never assume   Whether canaries are "on" is what is on disk. canaries.json in the
                              state folder only says what to look for.
    Only its own files        Taking a set away deletes a decoy only while it is still, byte for
                              byte, the decoy that was placed. Anything else at that path stays.
    Unknown is not guilty     A decoy that cannot be read just now (it is in use, or its cloud
                              folder is offline) is reported as unread, not as changed.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import json
import os
import random
import re
import secrets
import stat
import struct
import textwrap
import time
import zipfile
import zlib
from pathlib import Path
from xml.sax.saxutils import escape

from . import paths, reg, util, winapi

VERSION = 1
KINDS = ("docx", "xlsx", "pdf", "png")
# Nothing HostGuard places is a hundredth of this. A larger file at a canary's path is someone's own.
MAX_BYTES = 16 << 20
WATCHED_ATTRIBUTES = (winapi.FILE_ATTRIBUTE_READONLY | winapi.FILE_ATTRIBUTE_HIDDEN | winapi.FILE_ATTRIBUTE_SYSTEM
                      | winapi.FILE_ATTRIBUTE_ENCRYPTED)

_FOLDER_WORDS = ("Archive", "Backup", "Old documents", "Paperwork", "Records", "Scans")
_FOLDER_RE = re.compile(r"^![A-Za-z ]{3,24} [0-9a-f]{4}$")
_FILE_RE = re.compile(r"^[A-Za-z0-9 ]{1,60}\.(docx|xlsx|pdf|png)$")
_BESIDE_RE = re.compile(r"^![A-Za-z ]{3,24} [0-9a-f]{4}\.(docx|xlsx|pdf)$")
_NAMES = {
    "docx": ("Meeting notes", "Cover letter", "Project plan", "Reference letter", "Trip itinerary", "Minutes"),
    "xlsx": ("Household budget", "Expenses", "Inventory", "Mileage log", "Savings plan", "Price list"),
    "pdf": ("Invoice 1042", "Statement", "Insurance policy", "Tax summary", "Receipt", "Warranty"),
    "png": ("Scan 001", "Floor plan", "Diagram", "Whiteboard", "Site map", "Sketch"),
}
_ABOUT = ("This file is a HostGuard canary. HostGuard put it here because ransomware rewrites every document it "
          "reaches, and it would reach this one early. HostGuard compares its canaries with what it placed and raises "
          "an alarm when one of them changes, so please leave this file as it is. To remove the canaries, turn off "
          "Canary files on the Hardening tab of the HostGuard dashboard, or run: hostguard canary off")
_SPENT_ON = ("rent", "groceries", "insurance", "fuel", "phone", "electricity", "water", "internet", "repairs", "books",
             "travel", "gifts", "subscriptions", "tools", "furniture", "tickets", "parking", "postage")

# Files that programs leave beside a document while it is open, or that Explorer adds to any folder.
_BYSTANDER = re.compile(r"^(?:desktop\.ini|thumbs\.db|~\$.*|~.*\.tmp|\.~lock\..*#)$", re.I)
_NOTE = re.compile(r"read[ _.-]?me|decrypt|recover|restore|ransom|how[ _.-]?to|instruction|unlock|your[ _.-]?files|payment|!!!",
                   re.I)
_NOTE_EXT = {"", ".txt", ".html", ".htm", ".hta", ".url", ".rtf", ".bmp", ".png", ".jpg"}


def manifest_path() -> Path:
    return paths.home() / "canaries.json"


# ------------------------------------------------------------------ the decoys

def _ledger(rng: random.Random, count: int) -> list[tuple[str, str, str]]:
    day = _dt.date(rng.randint(2016, 2022), rng.randint(1, 12), rng.randint(1, 28))
    rows = []
    for _ in range(count):
        day += _dt.timedelta(days=rng.randint(1, 9))
        rows.append((day.isoformat(), rng.choice(_SPENT_ON).capitalize(), f"{rng.uniform(4, 900):.2f}"))
    return rows


_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_OFFICE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_TYPES = (_XML + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>{overrides}</Types>')
_OVERRIDE = '<Override PartName="{part}" ContentType="application/vnd.openxmlformats-officedocument.{type}+xml"/>'
_RELS = (_XML + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="' + _OFFICE + '/{kind}" Target="{target}"/></Relationships>')


def _package(parts: list[tuple[str, str]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts:
            z.writestr(zipfile.ZipInfo(name), text.encode("utf-8"), zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def _docx(rng: random.Random) -> bytes:
    lines = [_ABOUT] + ["   ".join(row) for row in _ledger(rng, rng.randint(500, 1400))]
    body = "".join(f'<w:p><w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>' for line in lines)
    document = (_XML + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                + body + "<w:sectPr/></w:body></w:document>")
    return _package([
        ("[Content_Types].xml", _TYPES.format(overrides=_OVERRIDE.format(part="/word/document.xml", type="wordprocessingml.document.main"))),
        ("_rels/.rels", _RELS.format(kind="officeDocument", target="word/document.xml")),
        ("word/document.xml", document)])


def _xlsx(rng: random.Random) -> bytes:
    rows = [f'<row r="1"><c r="A1" t="inlineStr"><is><t>{escape(_ABOUT)}</t></is></c></row>']
    for n, (day, what, amount) in enumerate(_ledger(rng, rng.randint(500, 1400)), 2):
        rows.append(f'<row r="{n}"><c r="A{n}" t="inlineStr"><is><t>{day}</t></is></c>'
                    f'<c r="B{n}" t="inlineStr"><is><t>{what}</t></is></c><c r="C{n}"><v>{amount}</v></c></row>')
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    sheet = _XML + f'<worksheet xmlns="{main}"><sheetData>' + "".join(rows) + "</sheetData></worksheet>"
    book = (_XML + f'<workbook xmlns="{main}" xmlns:r="{_OFFICE}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/>'
            "</sheets></workbook>")
    overrides = (_OVERRIDE.format(part="/xl/workbook.xml", type="spreadsheetml.sheet.main")
                 + _OVERRIDE.format(part="/xl/worksheets/sheet1.xml", type="spreadsheetml.worksheet"))
    return _package([
        ("[Content_Types].xml", _TYPES.format(overrides=overrides)),
        ("_rels/.rels", _RELS.format(kind="officeDocument", target="xl/workbook.xml")),
        ("xl/workbook.xml", book),
        ("xl/_rels/workbook.xml.rels", _RELS.format(kind="worksheet", target="worksheets/sheet1.xml")),
        ("xl/worksheets/sheet1.xml", sheet)])


def _pdf(rng: random.Random) -> bytes:
    lines = textwrap.wrap(_ABOUT, 92) + [""] + ["     ".join(row) for row in _ledger(rng, rng.randint(250, 700))]
    pages = [lines[i:i + 50] for i in range(0, len(lines), 50)]
    # Objects 1 to 3 are the catalogue, the page list and the font. Each page then takes two: itself and its text.
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(len(pages)))
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode(),
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    for i, page in enumerate(pages):
        shown = " ".join("(" + line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ") Tj T*" for line in page)
        text = f"BT /F1 10 Tf 14 TL 56 780 Td {shown} ET".encode("latin-1", "replace")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> "
                       f"/Contents {5 + 2 * i} 0 R >>".encode())
        objects.append(b"<< /Length " + str(len(text)).encode() + b" >>\nstream\n" + text + b"\nendstream")
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
    table = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{table}\n%%EOF\n".encode()
    return bytes(out)


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def _png(rng: random.Random) -> bytes:
    """A picture of soft blocks of colour, big enough to pass for a scan."""
    width, height, cell = 640, 448, 8
    base = [rng.randint(60, 200) for _ in range(3)]
    rows = []
    for _y in range(height // cell):
        line = bytearray()
        for _x in range(width // cell):
            line += bytes(max(0, min(255, c + rng.randint(-45, 45))) for c in base) * cell
        rows.append((b"\x00" + bytes(line)) * cell)       # every row of pixels starts with its filter type: none
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + _png_chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + _png_chunk(b"IEND", b""))


_MAKERS = {"docx": _docx, "xlsx": _xlsx, "pdf": _pdf, "png": _png}


def sound(kind: str, data: bytes) -> bool:
    """Is this still a document of its kind that a program could open?

    An editor or a sync service that changes a document leaves a sound one behind. Encryption does
    not: the checksums inside a Word, Excel or PNG file no longer match, and a PDF loses its header or
    the table that says where its parts are. (A PDF carries no checksum, so damage that falls only
    inside its text can pass. The other three kinds in the same folder do not let it.)
    """
    try:
        if kind in ("docx", "xlsx"):
            if not data.startswith(b"PK\x03\x04"):
                return False
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                if sum(i.file_size for i in z.infolist()) > 256 << 20:
                    return True                          # too much to unpack just to check: leave it be
                wanted = "word/document.xml" if kind == "docx" else "xl/workbook.xml"
                return wanted in z.namelist() and z.testzip() is None
        if kind == "pdf":
            m = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", data[-2048:])
            if not data.startswith(b"%PDF-") or not m or int(m.group(1)) >= len(data):
                return False
            table = int(m.group(1))
            if not data.startswith(b"xref", table):
                return re.match(rb"\d+\s+\d+\s+obj", data[table:table + 24]) is not None    # a newer PDF keeps its table packed
            # Every object the table lists has to be where the table says it is.
            listed = re.findall(rb"(\d{10}) \d{5} n", data[table:data.find(b"trailer", table)])
            return bool(listed) and all(re.match(rb"\d+ \d+ obj", data[int(o):int(o) + 24]) for o in listed)
        if kind == "png":
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                return False
            at, tags = 8, []
            while at + 12 <= len(data):
                size = struct.unpack_from(">I", data, at)[0]
                tag, body = data[at + 4:at + 8], data[at + 8:at + 8 + size]
                if len(body) != size or data[at + 8 + size:at + 12 + size] != struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF):
                    return False
                tags.append(tag)
                at += 12 + size
            return at == len(data) and tags[:1] == [b"IHDR"] and tags[-1:] == [b"IEND"] and b"IDAT" in tags
    except Exception:       # a damaged archive can fail in many ways, and every one of them means: not sound
        return False
    return False


# ------------------------------------------------------------------ owner, permissions and attributes

_WHO = {"WD": "Everyone", "BA": "Administrators", "SY": "SYSTEM", "AU": "Authenticated Users", "BU": "Users",
        "IU": "Interactive users", "CO": "Creator Owner", "AN": "Anonymous", "BG": "Guests", "NU": "Network users",
        "AC": "All app packages", "OW": "Owner rights", "LA": "the Administrator account", "DA": "Domain Admins"}
_RIGHTS = {"FA": "full control", "GA": "full control", "FR": "read", "GR": "read", "FW": "write", "GW": "write",
           "FX": "run", "GX": "run", "0x1301bf": "modify", "0x1200a9": "read and run", "0x1201bf": "read and write",
           "0x1f01ff": "full control", "0x120089": "read", "0x120116": "write"}
_ATTRIBUTE_NAMES = ((winapi.FILE_ATTRIBUTE_READONLY, "Read-only"), (winapi.FILE_ATTRIBUTE_HIDDEN, "Hidden"),
                    (winapi.FILE_ATTRIBUTE_SYSTEM, "System"))


def _attributes(st: os.stat_result) -> int:
    return int(getattr(st, "st_file_attributes", 0)) & WATCHED_ATTRIBUTES


def _security(path: str, st: os.stat_result) -> str | None:
    """Owner and permissions as text that can be compared later. Windows gives SDDL; elsewhere the
    owner's number and the mode bits stand in, so the comparison can be tested on any system."""
    if winapi.IS_WINDOWS:
        return winapi.file_security(path)
    return f"uid:{st.st_uid} mode:{stat.S_IMODE(st.st_mode):o}"


def _who(sid: str) -> str:
    return _WHO.get(sid, sid)


def describe_entry(entry: str) -> str:
    """One entry of a Windows access list in words: "allow Everyone full control"."""
    parts = entry.split(";")
    if len(parts) < 6:
        return entry
    kind = {"A": "allow", "D": "deny"}.get(parts[0], parts[0])
    return f"{kind} {_who(parts[5])} {_RIGHTS.get(parts[2], _RIGHTS.get(parts[2].lower(), parts[2]))}"


def split_security(text: str) -> dict:
    """{"owner", "protected", "own": entries set on the item itself, "handed_down": entries from the folder above}"""
    m = re.match(r"^O:(?P<owner>.*?)(?:G:.*?)?D:(?P<flags>[A-Z]*)(?P<entries>(?:\([^)]*\))*)", text or "")
    if not m:                                           # the stand-in used off Windows: "uid:1000 mode:644"
        owner, _, mode = (text or "").partition(" ")
        return {"owner": owner, "protected": False, "own": {mode} if mode else set(), "handed_down": set()}
    own, handed_down = set(), set()
    for entry in re.findall(r"\(([^)]*)\)", m.group("entries")):
        flags = (entry.split(";") + ["", ""])[1]
        (handed_down if "ID" in [flags[i:i + 2] for i in range(0, len(flags), 2)] else own).add(entry)
    return {"owner": m.group("owner"), "protected": "P" in m.group("flags"), "own": own, "handed_down": handed_down}


def _security_changes(was: str | None, now: str | None) -> list[dict]:
    if not was or was == now:
        return []
    if not now:
        return [{"kind": "unread", "text": "its owner and permissions could not be read"}]
    a, b = split_security(was), split_security(now)
    out = []
    if a["owner"] != b["owner"]:
        out.append({"kind": "owner", "text": f"the owner changed from {_who(a['owner'])} to {_who(b['owner'])}"})
    out += [{"kind": "access", "text": "permission added: " + describe_entry(e)} for e in sorted(b["own"] - a["own"])]
    out += [{"kind": "access", "text": "permission removed: " + describe_entry(e)} for e in sorted(a["own"] - b["own"])]
    if a["protected"] != b["protected"]:
        out.append({"kind": "access", "text": "it no longer takes permissions from the folder above" if b["protected"]
                    else "it takes permissions from the folder above again"})
    if a["handed_down"] != b["handed_down"]:
        added = [describe_entry(e) for e in sorted(b["handed_down"] - a["handed_down"])]
        gone = [describe_entry(e) for e in sorted(a["handed_down"] - b["handed_down"])]
        out.append({"kind": "inherited", "text": "permissions handed down from the folder above changed"
                    + (": now also " + ", ".join(added) if added else "") + ("; no longer " + ", ".join(gone) if gone else "")})
    return out      # empty when the list was only rewritten: the same owner and the same entries are not a change


def _attribute_changes(was: int, now: int) -> list[dict]:
    out = []
    if (now & winapi.FILE_ATTRIBUTE_ENCRYPTED) and not (was & winapi.FILE_ATTRIBUTE_ENCRYPTED):
        out.append({"kind": "encrypted", "text": "Windows' own file encryption (EFS) was switched on for it"})
    for bit, name in _ATTRIBUTE_NAMES:
        if (was ^ now) & bit:
            out.append({"kind": "attribute", "text": f"it was marked {name}" if now & bit else f"its {name} mark was cleared"})
    return out


# ------------------------------------------------------------------ the record of what was placed

def _empty() -> dict:
    return {"version": VERSION, "placed": None, "folders": []}


def _valid(data) -> bool:
    """The record names only what HostGuard could have placed: decoy files directly inside a canary
    folder directly inside its root. Removing a set deletes by this record, so nothing else may be in it."""
    if not isinstance(data, dict) or not isinstance(data.get("folders"), list):
        return False
    for folder in data["folders"]:
        if not isinstance(folder, dict) or not all(isinstance(folder.get(k), str) and folder[k] for k in ("root", "path")):
            return False
        name = os.path.basename(folder["path"])
        if not _FOLDER_RE.match(name) or os.path.normcase(os.path.join(folder["root"], name)) != os.path.normcase(folder["path"]):
            return False
        files = folder.get("files")
        if not isinstance(files, list) or not files:
            return False
        beside = folder.get("beside")
        if beside is not None and not (isinstance(beside, dict) and isinstance(beside.get("name"), str)
                                       and _BESIDE_RE.match(beside["name"]) and beside["name"].rsplit(".", 1)[0] == name):
            return False
        for f in files + ([beside] if beside else []):
            if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not isinstance(f.get("sha256"), str) \
                    or not isinstance(f.get("size"), int) or not (f is beside or _FILE_RE.match(f["name"])):
                return False
    return True


def load() -> tuple[dict, str]:
    """(the record, how the record is). "none": nothing was ever placed. "ok". "damaged": the file is
    there and is not a record. "unread": it could not be opened just now."""
    for attempt in range(3):
        try:
            raw = manifest_path().read_bytes()
            break
        except FileNotFoundError:
            return _empty(), "none"
        except OSError:
            time.sleep(0.05 * (attempt + 1))            # another HostGuard process may be replacing it this instant
    else:
        return _empty(), "unread"
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return _empty(), "damaged"
    return (data, "ok") if _valid(data) else (_empty(), "damaged")


def _save(data: dict) -> None:
    paths.atomic_write(manifest_path(), json.dumps(data, indent=1))


# ------------------------------------------------------------------ where they go

_SHELL_FOLDERS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
# the name Windows keeps the folder's real location under, its usual name, what to call it
_KNOWN_FOLDERS = (("Desktop", "Desktop", "Desktop"), ("Personal", "Documents", "Documents"),
                  ("My Pictures", "Pictures", "Pictures"), ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads", "Downloads"),
                  ("My Music", "Music", "Music"), ("My Video", "Videos", "Videos"))


def roots(cfg: dict | None = None) -> list[dict]:
    """Where a new set of canaries would go: [{"root": folder, "label": what it is}].

    The top of each fixed drive comes first, because a program that starts at the top of a drive
    meets that canary before anything else. Then the profile folder and the folders people keep
    their files in, wherever Windows says those really are (OneDrive often moves them).

    HOSTGUARD_CANARY_ROOTS (folders separated like PATH) replaces the whole list. The tests use it
    so that they never write into a real profile.
    """
    override = os.environ.get("HOSTGUARD_CANARY_ROOTS")
    if override is not None:
        found = [(p, "set by HOSTGUARD_CANARY_ROOTS") for p in override.split(os.pathsep)]
    else:
        c = (cfg or paths.load_config()).get("canary") or {}
        user = os.environ.get("USERPROFILE") or str(Path.home())
        found = [(d, f"the top of drive {d[:2]}") for d in winapi.fixed_drives()] if c.get("drive_roots", True) else []
        found.append((user, "your profile folder"))
        shell = reg.values(reg.HKCU, _SHELL_FOLDERS)
        for value, usual, label in _KNOWN_FOLDERS:
            raw = shell.get(value)
            found.append((os.path.expandvars(raw) if isinstance(raw, str) and raw else os.path.join(user, usual), label))
        found.append((os.path.join(os.environ.get("PUBLIC") or r"C:\Users\Public", "Documents"), "Public Documents"))
        found += [(d, "a folder you added") for d in c.get("extra_dirs") or []]
    out, seen = [], set()
    for path, label in found:
        path = str(path).strip().strip('"')
        if not path:
            continue
        path = os.path.abspath(path)
        key = os.path.normcase(path).rstrip("\\/")
        if key not in seen and os.path.isdir(path):
            seen.add(key)
            out.append({"root": path, "label": label})
    return out


# ------------------------------------------------------------------ placing and removing

def _why(e: OSError) -> str:
    if isinstance(e, FileExistsError):
        return "something with that name is already there"
    if isinstance(e, PermissionError):
        return ("Windows refused. If Controlled folder access is on, it stops programs it does not know from writing "
                "there until you allow them")
    return str(e.strerror or e)


def _write_decoy(path: str, kind: str, rng: random.Random) -> bytes:
    data = _MAKERS[kind](rng)
    with open(path, "xb") as f:            # fails if anything is already there: nothing of anyone's is ever written over
        f.write(data)
    aged = time.time() - rng.uniform(250, 1600) * 86400
    os.utime(path, (aged, aged))
    return data


def _recorded(path: str, name: str, kind: str, data: bytes) -> dict:
    """What goes into the record for one decoy, taken from what is on disk and not from what was meant."""
    st = os.stat(path)
    with open(path, "rb") as f:
        if f.read(len(data) + 1) != data:
            raise OSError(0, "a file read back differently from what was written")
    return {"name": name, "kind": kind, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "security": _security(path, st), "attributes": _attributes(st)}


def _place_one(where: dict, name: str, rng: random.Random) -> dict:
    root = where["root"]
    folder = os.path.join(root, name)
    os.mkdir(folder)                       # fails if anything is already there: never write into a folder HostGuard did not make
    made: list[str] = []
    try:
        written = []
        for kind in KINDS:
            file_name = rng.choice(_NAMES[kind]) + (f" {rng.randint(2015, 2023)}" if rng.random() < 0.6 else "") + "." + kind
            path = os.path.join(folder, file_name)
            data = _write_decoy(path, kind, rng)
            made.append(path)
            written.append((file_name, kind, path, data))
        if util.is_redirected(folder):
            raise OSError(0, "this Python is the Microsoft Store edition, which can only write a private copy inside AppData")
        if winapi.IS_WINDOWS and not winapi.set_hidden(folder):
            raise OSError(0, "the folder could not be hidden")
        files = [_recorded(path, file_name, kind, data) for file_name, kind, path, data in written]
        st = os.stat(folder)
        placed = {"root": root, "label": where["label"], "path": folder, "volume": os.stat(root).st_dev,
                  "security": _security(folder, st), "attributes": _attributes(st), "files": files}
    except BaseException:
        for path in made:
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            os.rmdir(folder)
        except OSError:
            pass
        raise
    # One more decoy directly beside the folder, for a program that takes a folder's own files before it goes
    # into the subfolders. Some places take a folder and not a file (the top of the system drive): then there is none.
    kind = rng.choice(("docx", "xlsx", "pdf"))
    beside = os.path.join(root, f"{name}.{kind}")
    try:
        data = _write_decoy(beside, kind, rng)
    except OSError:
        return placed
    try:
        if winapi.IS_WINDOWS and not winapi.set_hidden(beside):
            raise OSError(0, "the file could not be hidden")
        placed["beside"] = _recorded(beside, os.path.basename(beside), kind, data)
    except OSError:
        try:
            os.remove(beside)
        except OSError:
            pass
    return placed


def place(cfg: dict | None = None, log=None) -> dict:
    """Put a new set of canaries down and record it. A set that is already out is taken away first."""
    log = log or (lambda _m: None)
    old, record = load()
    if record == "unread":
        return {"ok": False, "message": "the record of the canaries could not be opened just now; try again", "folders": 0,
                "files": 0, "failed": []}
    if old["folders"]:
        log(remove(log=log)["message"])
    elif record == "damaged":
        log("the old record of the canaries could not be understood; it is replaced and nothing it named is deleted")
    where = roots(cfg)
    if not where:
        return {"ok": False, "message": "there is no folder to put a canary in", "folders": 0, "files": 0, "failed": []}
    name = "!" + secrets.choice(_FOLDER_WORDS) + " " + secrets.token_hex(2)
    rng = random.Random(secrets.randbits(64))
    folders, failed = [], []
    for w in where:
        try:
            folders.append(_place_one(w, name, rng))
            log(f"placed {folders[-1]['path']}")
        except OSError as e:
            failed.append({"root": w["root"], "why": _why(e)})
            log(f"nothing placed in {w['root']}: {_why(e)}")
    _save({"version": VERSION, "placed": time.time() if folders else None, "folders": folders})
    files = sum(len(_decoys(f)) for f in folders)
    if not folders:
        return {"ok": False, "message": "no canary could be placed: " + failed[0]["why"], "folders": 0, "files": 0, "failed": failed}
    message = f"placed {files} canary files in {len(folders)} place(s) under the name {name}"
    if failed:
        message += f"; {len(failed)} place(s) could not take one: " + "; ".join(f["root"] for f in failed[:4])
    return {"ok": True, "message": message, "folders": len(folders), "files": files, "failed": failed, "name": name}


def remove(log=None) -> dict:
    """Take the canaries away. A decoy is deleted only if it is still exactly what was placed."""
    log = log or (lambda _m: None)
    record_file, state = load()
    if state in ("damaged", "unread"):
        return {"ok": False, "removed": 0, "kept": [], "message":
                "the record of the canaries cannot be read, so nothing is deleted. Their folders start with an "
                "exclamation mark and are hidden; delete them by hand if you want them gone"}
    # The record goes first. Anything watching then sees canaries that were switched off, never canaries disappearing.
    _save({**_empty(), "removed": time.time()})
    removed, kept = 0, []
    for folder in record_file["folders"]:
        for path, rec in _decoys(folder):
            try:
                st = os.stat(path)
            except OSError:
                continue                                            # already gone
            try:
                if not stat.S_ISREG(st.st_mode) or st.st_size != rec["size"] or util.sha256_file(path) != rec["sha256"]:
                    kept.append(path)
                    continue
                if not os.access(path, os.W_OK):
                    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                os.remove(path)
                removed += 1
            except OSError:
                kept.append(path)
        try:
            os.rmdir(folder["path"])                                # only an empty folder goes
        except OSError:
            pass
    message = f"removed {removed} canary file(s)"
    if kept:
        message += f"; left {len(kept)} that had been changed where they are: " + "; ".join(kept[:4])
        log("left in place: " + "; ".join(kept))
    return {"ok": True, "removed": removed, "kept": kept, "message": message}


# ------------------------------------------------------------------ checking

def _decoys(folder: dict) -> list[tuple[str, dict]]:
    """(path, record) for every decoy of one canary: the ones in its folder, then the one beside it."""
    inside = [(os.path.join(folder["path"], f["name"]), f) for f in folder["files"]]
    return inside + ([(os.path.join(folder["root"], folder["beside"]["name"]), folder["beside"])] if folder.get("beside") else [])


def _check_file(path: str, rec: dict, seen: dict | None = None) -> dict:
    """`seen` remembers the size and time of each decoy when it was last read and found intact. A decoy
    whose size and time are still those is not read again: that is what lets a monitor look every few
    seconds for almost nothing. The caller empties `seen` now and then so that every decoy is read."""
    out = {"name": rec["name"], "kind": rec.get("kind") or rec["name"].rsplit(".", 1)[-1], "path": path, "state": "intact", "changes": []}
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return {**out, "state": "missing"}
    except OSError:
        return {**out, "state": "unread"}
    if not stat.S_ISREG(st.st_mode):
        return {**out, "state": "missing"}                          # something else now has its name
    data, stamp = None, (st.st_size, st.st_mtime_ns)
    if seen is not None and seen.get(path) == stamp:
        out["changes"] = _security_changes(rec.get("security"), _security(path, st)) \
            + _attribute_changes(int(rec.get("attributes") or 0), _attributes(st))
        return out
    try:
        f = open(path, "rb")
    except PermissionError:
        # Refused by the file's access list means HostGuard was locked out of its own file. Refused because
        # another program has it open and shares nothing is only "not now".
        refused = winapi.may_read(path) is False if winapi.IS_WINDOWS else True
        out["state"] = "locked" if refused else "unread"
    except OSError:
        out["state"] = "unread"
    else:
        with f:
            try:
                data = f.read(MAX_BYTES + 1)
            except OSError:                 # a part of it is locked by the program using it, or its cloud copy cannot be fetched
                out["state"] = "unread"
    if data is not None and (len(data) != rec["size"] or hashlib.sha256(data).hexdigest() != rec["sha256"]):
        out["was_bytes"], out["now_bytes"], out["starts_with"] = rec["size"], st.st_size, data[:8].hex()
        out["state"] = "edited" if len(data) > MAX_BYTES or sound(out["kind"], data) else "damaged"
    if seen is not None:
        if data is not None and out["state"] == "intact":
            seen[path] = stamp
        else:
            seen.pop(path, None)
    out["changes"] = _security_changes(rec.get("security"), _security(path, st)) \
        + _attribute_changes(int(rec.get("attributes") or 0), _attributes(st))
    return out


def _check_folder(rec: dict, seen: dict | None = None) -> dict:
    out = {"root": rec["root"], "label": rec.get("label") or "", "path": rec["path"], "state": "intact", "files": [],
           "strangers": [], "changes": []}
    try:
        there = os.stat(rec["root"])
        same_disk = rec.get("volume") is None or there.st_dev == rec["volume"]
    except OSError:
        same_disk = False
    if not same_disk or not os.path.isdir(rec["root"]):
        # The folder above is gone or is a different disk now (an unplugged drive, a moved OneDrive). Nothing is known.
        out["files"] = [{"name": f["name"], "kind": f.get("kind"), "path": path, "state": "unavailable", "changes": []}
                        for path, f in _decoys(rec)]
        return {**out, "state": "unavailable"}
    out["files"] = [_check_file(path, f, seen) for path, f in _decoys(rec)]
    names = {f["name"].lower() for f in rec["files"]}
    beside = rec.get("beside")
    if beside and out["files"][-1]["state"] == "missing":
        # The decoy beside the folder is gone. Is the same name there with something added (file.docx.locked)?
        stem = os.path.basename(rec["path"]).lower() + "."
        try:
            with os.scandir(rec["root"]) as entries:
                for e in entries:
                    if e.name.lower().startswith(stem) and e.name.lower() != beside["name"].lower() and e.is_file(follow_symlinks=False):
                        out["strangers"].append({"name": e.name, "bytes": e.stat(follow_symlinks=False).st_size,
                                                 "twin_of": beside["name"], "note": False, "beside": True})
        except OSError:
            pass
    try:
        st = os.stat(rec["path"])
        with os.scandir(rec["path"]) as entries:
            for e in entries:
                if e.name.lower() in names or _BYSTANDER.match(e.name):
                    continue
                try:
                    size = e.stat(follow_symlinks=False).st_size if e.is_file(follow_symlinks=False) else None
                except OSError:
                    size = None
                twin = next((f["name"] for f in rec["files"] if e.name.lower().startswith(f["name"].lower())
                             or e.name.lower().startswith(f["name"].rsplit(".", 1)[0].lower() + ".")), None)
                note = bool(_NOTE.search(e.name)) and os.path.splitext(e.name)[1].lower() in _NOTE_EXT and not twin
                out["strangers"].append({"name": e.name, "bytes": size, "twin_of": twin, "note": note, "beside": False})
        out["changes"] = _security_changes(rec.get("security"), _security(rec["path"], st)) \
            + _attribute_changes(int(rec.get("attributes") or 0), _attributes(st))
    except (FileNotFoundError, NotADirectoryError):
        return {**out, "state": "missing"}
    except OSError:
        out["changes"] = [{"kind": "unread", "text": "the folder could not be opened"}]
    out["strangers"].sort(key=lambda s: s["name"].lower())
    touched = out["strangers"] or out["changes"] or any(f["state"] not in ("intact", "unread") or f["changes"] for f in out["files"])
    return {**out, "state": "changed" if touched else "intact"}


def _summary(folders: list[dict]) -> dict:
    files = [f for fo in folders for f in fo["files"]]
    s = {"folders": len(folders), "files": len(files), "strangers": sum(len(fo["strangers"]) for fo in folders)}
    for state in ("intact", "edited", "damaged", "missing", "locked", "unread", "unavailable"):
        s[state] = sum(1 for f in files if f["state"] == state)
    s["untouched"] = sum(1 for f in files if f["state"] == "intact" and not f["changes"])
    s["folders_changed"] = sum(1 for fo in folders if fo["state"] in ("changed", "missing"))
    return s


def check(remembered: dict | None = None, seen: dict | None = None) -> dict:
    """The state of every canary, as facts.

    `remembered` is the last record a long-running caller read. If the record on disk has since gone
    or become unreadable, the remembered canaries are checked instead and the report says so: whatever
    rewrote the files may have rewritten the record of them too. `seen` is explained at _check_file.
    """
    report: dict = {}
    for attempt in (1, 2):
        on_disk, record = load()
        using = on_disk
        if record != "ok" and remembered and remembered.get("folders"):
            using, record = remembered, ("lost" if record == "none" else record)
        folders = [_check_folder(f, seen) for f in using["folders"]]
        report = {"record": record, "placed": using.get("placed"), "folders": folders, "summary": _summary(folders),
                  "checked": time.time(), "manifest": using}
        if attempt == 2 or all(f["state"] in ("intact", "unavailable") for f in folders) or load()[0] == on_disk:
            break       # looked a second time only if the record changed mid-check: a set being replaced is not an alarm
    return report


def _folder_note(folder: dict) -> str:
    if folder["state"] == "unavailable":
        return "the folder above it is not there now, so it cannot be checked"
    if folder["state"] == "missing":
        return "the canary folder is gone"
    counts: dict[str, int] = {}
    for f in folder["files"]:
        counts[f["state"]] = counts.get(f["state"], 0) + 1
    words = {"damaged": "no longer a document", "missing": "missing", "edited": "edited", "locked": "locked against HostGuard",
             "unread": "could not be read just now"}
    parts = [f"{n} {words[k]}" for k, n in counts.items() if k in words]
    if folder["strangers"]:
        parts.append(f"{len(folder['strangers'])} new file(s) beside them")
    if folder["changes"] or any(f["changes"] for f in folder["files"]):
        parts.append("permissions or attributes changed")
    return ", ".join(parts)


def brief(report: dict) -> dict:
    """What the dashboard and the command line show: totals, and each place with what is wrong there."""
    s = report["summary"]
    return {"on": bool(report["folders"]), "record": report["record"], "placed": report.get("placed"), "checked": report["checked"],
            "folders": s["folders"], "files": s["files"], "untouched": s["untouched"], "unread": s["unread"] + s["unavailable"],
            "changed": s["files"] - s["untouched"] - s["unread"] - s["unavailable"], "folders_changed": s["folders_changed"],
            "places": [{"path": f["path"], "label": f["label"], "state": f["state"], "note": _folder_note(f)} for f in report["folders"]]}
