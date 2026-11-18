"""Ransomware canaries: placing them, noticing each kind of change, and what each change is called.

Every test works in folders it creates itself. HOSTGUARD_CANARY_ROOTS points the canaries at those
folders, and is empty the rest of the time, so nothing here can write into a real profile."""

import contextlib
import io
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import xml.dom.minidom
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-canary-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")
os.environ["HOSTGUARD_CANARY_ROOTS"] = ""

from hostguard import canary, cli, monitor, notify, paths, scan, winapi  # noqa: E402
from hostguard.detect import canary as d_canary  # noqa: E402
from hostguard.model import GONE, OPEN, RESOLVED  # noqa: E402
from hostguard.store import Store  # noqa: E402

UNSIGNED = {"status": "NotSigned", "signer": "", "issuer": "", "is_os": False}
VENDOR = {"status": "Valid", "signer": "CN=Example Software Ltd", "issuer": "", "is_os": False}
MS = {"status": "Valid", "signer": "CN=Microsoft Windows, O=Microsoft Corporation", "issuer": "", "is_os": True}
EVERYONE, GUESTS = "*S-1-1-0", "*S-1-5-32-546"


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder
    os.environ["HOSTGUARD_CANARY_ROOTS"] = ""


def tearDownModule():
    os.environ["HOSTGUARD_CANARY_ROOTS"] = ""                    # left empty on purpose: no later test can place one by accident
    shutil.rmtree(_TMP, ignore_errors=True)


def icacls(*args) -> None:
    subprocess.run(["icacls", *args], capture_output=True, check=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def resaved(data: bytes, part: str) -> bytes:
    """The same Word or Excel file as an editor would write it back: repacked, with one part changed."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            zout.writestr(name, zin.read(name).replace(b"</w:body>", b"<w:p/></w:body>") if name == part else zin.read(name))
    return out.getvalue()


class Decoys(unittest.TestCase):
    def test_each_decoy_is_a_document_a_program_can_open_and_says_what_it_is(self):
        rng = random.Random(3)
        made = {kind: canary._MAKERS[kind](rng) for kind in canary.KINDS}
        for kind, data in made.items():
            self.assertTrue(canary.sound(kind, data), kind)
            self.assertTrue(4000 < len(data) < 200000, (kind, len(data)))
        for kind, main in (("docx", "word/document.xml"), ("xlsx", "xl/worksheets/sheet1.xml")):
            with zipfile.ZipFile(io.BytesIO(made[kind])) as z:
                self.assertEqual(z.namelist()[0], "[Content_Types].xml")
                for name in z.namelist():
                    xml.dom.minidom.parseString(z.read(name))
                self.assertIn(b"HostGuard canary", z.read(main))
                self.assertIn(b"hostguard canary off", z.read(main))
        pdf = made["pdf"]
        self.assertIn(b"HostGuard canary", pdf)
        table = int(pdf.rsplit(b"startxref", 1)[1].split()[0])
        self.assertTrue(pdf.startswith(b"xref", table))
        self.assertEqual(pdf.count(b" 0 obj\n"), int(pdf[table:].split()[2]) - 1, "the table lists every object")
        self.assertEqual(made["png"][:8], b"\x89PNG\r\n\x1a\n")
        self.assertNotEqual(canary._MAKERS["docx"](random.Random(4)), made["docx"], "no two sets are the same bytes")

    def test_an_overwritten_decoy_is_not_sound_and_a_resaved_one_is(self):
        rng = random.Random(5)
        for kind in canary.KINDS:
            data = canary._MAKERS[kind](rng)
            head = os.urandom(4096) + data[4096:]                       # only the start encrypted
            for label, bad in (("noise", os.urandom(len(data))), ("empty", b""), ("cut short", data[:len(data) // 2]),
                               ("start encrypted", head), ("another kind", b"MZ" + data)):
                self.assertFalse(canary.sound(kind, bad), (kind, label))
        for kind in ("docx", "xlsx", "png"):                             # these carry checksums: damage anywhere shows
            data = canary._MAKERS[kind](rng)
            middle = len(data) // 2
            self.assertFalse(canary.sound(kind, data[:middle] + bytes(b ^ 0x55 for b in data[middle:middle + 64]) + data[middle + 64:]), kind)
        docx = canary._MAKERS["docx"](rng)
        self.assertTrue(canary.sound("docx", resaved(docx, "word/document.xml")))
        self.assertFalse(canary.sound("xlsx", docx), "a Word file is not a sound Excel file")
        self.assertFalse(canary.sound("txt", b"anything"))


class Permissions(unittest.TestCase):
    """Windows' access lists as text, compared without touching a disk."""
    ME = "S-1-5-21-1111111111-2222222222-3333333333-1001"
    BASE = f"O:{ME}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{ME})"

    def kinds(self, now):
        return [(c["kind"], c["text"]) for c in canary._security_changes(self.BASE, now)]

    def test_what_counts_as_a_change(self):
        self.assertEqual(self.kinds(self.BASE), [])
        self.assertEqual(self.kinds(self.BASE.replace("D:AI", "D:")), [], "a rewritten list with the same entries is not a change")
        self.assertEqual(self.kinds(f"O:{self.ME}D:AI(A;ID;FA;;;BA)(A;ID;FA;;;{self.ME})(A;ID;FA;;;SY)"), [], "nor is their order")
        self.assertEqual(self.kinds(self.BASE + "(A;;FA;;;WD)"), [("access", "permission added: allow Everyone full control")])
        self.assertEqual(self.kinds(self.BASE.replace(f"O:{self.ME}", "O:BA")), [("owner", f"the owner changed from {self.ME} to Administrators")])
        cut_off = f"O:{self.ME}D:PAI(A;;FA;;;SY)(A;;FA;;;{self.ME})"
        got = self.kinds(cut_off)
        self.assertIn(("access", "it no longer takes permissions from the folder above"), got)
        self.assertTrue(all(kind in ("access", "inherited") for kind, _ in got), got)
        handed = self.kinds(self.BASE + "(A;ID;0x1200a9;;;BG)")
        self.assertEqual(handed, [("inherited", "permissions handed down from the folder above changed: now also allow Guests read and run")])
        self.assertEqual(self.kinds(None), [("unread", "its owner and permissions could not be read")])
        self.assertEqual(canary._security_changes(None, self.BASE), [], "nothing was recorded, so nothing can have changed")

    def test_entries_and_marks_in_words(self):
        self.assertEqual(canary.describe_entry("D;;FW;;;BU"), "deny Users write")
        self.assertEqual(canary.describe_entry("A;OICI;0x1301bf;;;AU"), "allow Authenticated Users modify")
        self.assertEqual(canary.describe_entry("odd"), "odd")
        marks = [(c["kind"], c["text"]) for c in canary._attribute_changes(winapi.FILE_ATTRIBUTE_HIDDEN, winapi.FILE_ATTRIBUTE_READONLY | winapi.FILE_ATTRIBUTE_ENCRYPTED)]
        self.assertEqual(marks, [("encrypted", "Windows' own file encryption (EFS) was switched on for it"),
                                 ("attribute", "it was marked Read-only"), ("attribute", "its Hidden mark was cleared")])
        self.assertEqual(canary._attribute_changes(2, 2), [])


class Placed(unittest.TestCase):
    """A set of canaries in three throwaway folders, each of which also holds a file and a folder of its 'owner'."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="set-", dir=_TMP)
        self.roots = [os.path.join(self.work, name) for name in ("Documents", "Pictures", "Disk")]
        for root in self.roots:
            os.makedirs(os.path.join(root, "Alpha"))
            Path(root, "my own file.txt").write_text("mine")
        os.environ["HOSTGUARD_CANARY_ROOTS"] = os.pathsep.join(self.roots)
        self.addCleanup(self.reset)

    def reset(self):
        canary.remove()
        canary.manifest_path().unlink(missing_ok=True)
        os.environ["HOSTGUARD_CANARY_ROOTS"] = ""

    def place(self) -> list[dict]:
        res = canary.place()
        self.assertTrue(res["ok"], res)
        folders = canary.load()[0]["folders"]
        self.assertEqual(len(folders), 3)
        return folders

    def path(self, folder: dict, kind: str) -> str:
        return os.path.join(folder["path"], next(f["name"] for f in folder["files"] if f["kind"] == kind))

    def beside(self, folder: dict) -> str:
        return os.path.join(folder["root"], folder["beside"]["name"])

    def look(self):
        report = canary.check()
        found = d_canary.detect(report)
        self.assertLessEqual(len(found), 1)
        return report, (found[0] if found else None)

    def rule(self):
        f = self.look()[1]
        return (f.rule, f.severity, f.confidence) if f else None


class Placement(Placed):
    def test_a_canary_sorts_first_is_hidden_and_is_recorded_from_the_disk(self):
        self.assertEqual([w["root"] for w in canary.roots()], self.roots)
        res = canary.place()
        self.assertEqual((res["ok"], res["folders"], res["files"], res["failed"]), (True, 3, 15, []))
        record, state = canary.load()
        self.assertEqual(state, "ok")
        for folder, root in zip(record["folders"], self.roots):
            name = os.path.basename(folder["path"])
            self.assertEqual((folder["root"], name), (root, res["name"]))
            in_order = sorted(os.listdir(root), key=str.upper)
            lone = folder["beside"]["name"]
            self.assertEqual(in_order[:2], [name, lone], "a walk of the folder meets the canary first")
            self.assertEqual((os.path.splitext(lone)[0], folder["beside"]["kind"] in ("docx", "xlsx", "pdf")), (name, True))
            self.assertEqual([n for n in in_order if os.path.isfile(os.path.join(root, n))][0], lone, "and so does one that takes files first")
            self.assertTrue(canary.sound(folder["beside"]["kind"], Path(root, lone).read_bytes()))
            self.assertEqual(sorted(os.listdir(folder["path"])), sorted(f["name"] for f in folder["files"]))
            self.assertEqual(sorted(f["kind"] for f in folder["files"]), ["docx", "pdf", "png", "xlsx"])
            for f in folder["files"]:
                data = Path(folder["path"], f["name"]).read_bytes()
                self.assertEqual((len(data), canary.hashlib.sha256(data).hexdigest()), (f["size"], f["sha256"]))
                self.assertTrue(canary.sound(f["kind"], data))
                self.assertLess(os.stat(os.path.join(folder["path"], f["name"])).st_mtime, time.time() - 200 * 86400, "decoys look old")
            if WINDOWS:
                self.assertTrue(os.stat(folder["path"]).st_file_attributes & winapi.FILE_ATTRIBUTE_HIDDEN)
                self.assertTrue(os.stat(os.path.join(root, lone)).st_file_attributes & winapi.FILE_ATTRIBUTE_HIDDEN)
                self.assertEqual(folder["beside"]["attributes"], winapi.FILE_ATTRIBUTE_HIDDEN)
                self.assertTrue(folder["security"].startswith("O:") and all(f["security"] for f in folder["files"]))
            self.assertEqual(Path(root, "my own file.txt").read_text(), "mine")
        report, found = self.look()
        self.assertIsNone(found)
        self.assertEqual((report["summary"]["files"], report["summary"]["untouched"]), (15, 15))
        b = canary.brief(report)
        self.assertEqual((b["on"], b["changed"], b["folders"], [p["state"] for p in b["places"]]), (True, 0, 3, ["intact"] * 3))
        json.dumps(b)
        self.assertNotIn("manifest", b)

    def test_a_place_that_refuses_is_skipped_and_said(self):
        real = canary._place_one

        def refuse_pictures(where, name, rng):
            if where["root"].endswith("Pictures"):
                raise PermissionError(13, "Access is denied")
            return real(where, name, rng)
        lines = []
        with mock.patch.object(canary, "_place_one", refuse_pictures):
            res = canary.place(log=lines.append)
        self.assertEqual((res["ok"], res["folders"], res["files"]), (True, 2, 10))
        self.assertEqual([f["root"] for f in res["failed"]], [self.roots[1]])
        self.assertIn("Controlled folder access", res["failed"][0]["why"])
        self.assertIn("1 place(s) could not take one", res["message"])
        self.assertTrue(any("nothing placed in" in line for line in lines))
        self.assertEqual(os.listdir(self.roots[1]).count("Alpha"), 1)
        self.assertEqual(len(os.listdir(self.roots[1])), 2)

    def test_nothing_is_ever_written_into_a_folder_that_is_already_there(self):
        taken = os.path.join(self.roots[0], "!Archive abcd")
        os.makedirs(taken)
        Path(taken, "thesis.docx").write_text("years of work")
        theirs = [Path(self.roots[1], "!Archive abcd." + kind) for kind in ("docx", "xlsx", "pdf")]
        for f in theirs:
            f.write_text("mine too")
        with mock.patch.object(canary.secrets, "choice", return_value="Archive"), mock.patch.object(canary.secrets, "token_hex", return_value="abcd"):
            res = canary.place()
        self.assertEqual((res["folders"], res["files"], [f["root"] for f in res["failed"]]), (2, 9, [self.roots[0]]))
        self.assertIn("already there", res["failed"][0]["why"])
        self.assertEqual(os.listdir(taken), ["thesis.docx"])
        folders = canary.load()[0]["folders"]
        self.assertEqual([("beside" in f) for f in folders], [False, True], "where the file's name is taken, the folder goes down alone")
        self.assertIsNone(self.look()[1])
        self.assertTrue(canary.remove()["ok"])
        self.assertEqual(Path(taken, "thesis.docx").read_text(), "years of work")
        self.assertEqual([f.read_text() for f in theirs], ["mine too"] * 3)

    def test_a_half_made_canary_is_taken_back(self):
        with mock.patch.dict(canary._MAKERS, {"pdf": lambda rng: (_ for _ in ()).throw(OSError(28, "No space left on device"))}):
            res = canary.place()
        self.assertFalse(res["ok"])
        self.assertIn("No space left", res["message"])
        for root in self.roots:
            self.assertEqual(sorted(os.listdir(root)), ["Alpha", "my own file.txt"])
        self.assertEqual(canary.load()[0]["folders"], [])

    def test_removing_deletes_only_decoys_that_are_still_what_was_placed(self):
        a, b, c = self.place()
        Path(self.path(a, "xlsx")).write_text("my own spreadsheet now")          # someone saved their own work over a decoy
        Path(b["path"], "holiday.jpg").write_bytes(b"\xff\xd8 mine")             # and put a file of theirs beside others
        os.chmod(self.path(c, "pdf"), stat.S_IREAD)                              # a read-only decoy is still a decoy
        res = canary.remove()
        self.assertEqual((res["ok"], res["removed"], res["kept"]), (True, 14, [self.path(a, "xlsx")]))
        self.assertEqual(os.listdir(a["path"]), [os.path.basename(self.path(a, "xlsx"))])
        self.assertEqual(os.listdir(b["path"]), ["holiday.jpg"])
        self.assertFalse(os.path.exists(c["path"]))
        self.assertEqual(sorted(os.listdir(self.roots[2])), ["Alpha", "my own file.txt"], "the place is as it was found")
        self.assertEqual(sorted(os.listdir(self.roots[0])), [os.path.basename(a["path"]), "Alpha", "my own file.txt"])
        self.assertEqual(canary.load(), ({"version": 1, "placed": None, "folders": [], "removed": mock.ANY}, "ok"))
        self.assertIsNone(self.look()[1], "canaries that were switched off are not canaries that went missing")
        self.assertFalse(canary.brief(canary.check())["on"])
        self.assertEqual(canary.remove()["removed"], 0)

    def test_placing_again_puts_a_fresh_set_down(self):
        first = self.place()
        Path(self.path(first[0], "png")).write_bytes(os.urandom(64))
        lines = []
        with mock.patch.object(canary.secrets, "token_hex", return_value="0f0f"):
            res = canary.place(log=lines.append)
        second = canary.load()[0]["folders"]
        self.assertTrue(res["ok"])
        self.assertNotEqual(first[0]["path"], second[0]["path"])
        self.assertEqual(len(os.listdir(first[0]["path"])), 1, "the decoy that had changed stays as it was found")
        self.assertFalse(os.path.exists(first[1]["path"]))
        self.assertTrue(any("left 1 that had been changed" in line for line in lines), lines)
        self.assertIsNone(self.look()[1])

    def test_the_record_can_only_name_what_hostguard_could_have_placed(self):
        mine = Path(self.roots[0], "my own file.txt")
        digest, size = canary.hashlib.sha256(mine.read_bytes()).hexdigest(), mine.stat().st_size
        folder = os.path.join(self.roots[0], "!Archive abcd")
        good = {"root": self.roots[0], "path": folder, "files": [{"name": "Notes.docx", "kind": "docx", "sha256": digest, "size": size}]}
        forged = [
            {**good, "path": self.roots[0], "files": [{"name": "my own file.txt", "sha256": digest, "size": size}]},     # not a canary folder
            {**good, "path": os.path.join(self.roots[0], "Alpha")},
            {**good, "path": os.path.join(self.roots[1], "!Archive abcd")},                                             # not inside its root
            {**good, "files": [{"name": "..\\my own file.txt", "sha256": digest, "size": size}]},
            {**good, "files": [{"name": "my own file.txt", "sha256": digest, "size": size}]},                            # not a decoy's name
            {**good, "files": []},
            {**good, "files": [{"name": "Notes.docx", "sha256": digest}]},
        ]
        lone = {"name": "!Archive abcd.docx", "kind": "docx", "sha256": digest, "size": size}
        forged += [{**good, "beside": {**lone, "name": "my own file.txt"}},                                             # beside, but not a decoy's name
                   {**good, "beside": {**lone, "name": "!Other abcd.docx"}},                                            # not this canary's name
                   {**good, "beside": {**lone, "name": "!Archive abcd.docx\\..\\my own file.txt"}},
                   {**good, "beside": "!Archive abcd.docx"}]
        for i, folder_rec in enumerate(forged):
            canary._save({"version": 1, "placed": 1.0, "folders": [folder_rec]})
            self.assertEqual(canary.load(), (canary._empty(), "damaged"), i)
            res = canary.remove()
            self.assertEqual((res["ok"], res["removed"]), (False, 0), i)
            self.assertEqual(mine.read_text(), "mine")
        for junk in ("{ not json", "[1, 2]", '{"folders": "x"}', ""):
            canary.manifest_path().write_text(junk, encoding="utf-8")
            self.assertEqual(canary.load()[1], "damaged", junk)
        canary._save({"version": 1, "placed": 1.0, "folders": [good]})
        self.assertEqual(canary.load()[1], "ok")
        canary._save({"version": 1, "placed": 1.0, "folders": [{**good, "beside": lone}]})
        self.assertEqual(canary.load()[1], "ok")
        canary.manifest_path().unlink()
        self.assertEqual(canary.load(), (canary._empty(), "none"))

    def test_where_they_go_by_default(self):
        extra = os.path.join(self.work, "Projects")
        os.makedirs(extra)
        with mock.patch.dict(os.environ):
            del os.environ["HOSTGUARD_CANARY_ROOTS"]
            found = canary.roots({"canary": {"drive_roots": True, "extra_dirs": [extra, extra + os.sep, os.path.join(self.work, "nope")]}})
            without = canary.roots({"canary": {"drive_roots": False, "extra_dirs": []}})
        where = [w["root"] for w in found]
        self.assertEqual(len({os.path.normcase(p) for p in where}), len(where), "no folder twice")
        self.assertTrue(all(os.path.isdir(p) for p in where))
        self.assertEqual([w["label"] for w in found if w["root"] == extra], ["a folder you added"])
        labels = [w["label"] for w in found]
        self.assertIn("your profile folder", labels)
        if WINDOWS:
            drives = [w for w in found if w["label"].startswith("the top of drive")]
            self.assertTrue(drives and found[0] == drives[0], "a drive's top comes first: that is where a walk of the drive starts")
            self.assertEqual([w for w in without if w["label"].startswith("the top of drive")], [])
            if os.path.isdir(os.path.join(os.environ["USERPROFILE"], "Documents")):
                self.assertIn("Documents", labels)
        self.assertEqual(canary.roots(), [{"root": r, "label": "set by HOSTGUARD_CANARY_ROOTS"} for r in self.roots])


class Changes(Placed):
    """What each thing that can happen to a canary is called."""

    def test_overwriting_is_ransomware(self):
        a, b, _c = self.place()
        target = self.path(a, "docx")
        Path(target).write_bytes(os.urandom(os.path.getsize(target)))
        report, f = self.look()
        self.assertEqual((f.rule, f.severity, f.confidence, f.category, f.collector, f.kind), ("canary.ransomware", "critical", "high", "file", "canaries", "state"))
        self.assertEqual((f.actions, f.entity["type"], f.mitre), ([], "canary", ["T1486"]))
        self.assertIn("in 1 place", f.title)
        self.assertIn(target, f.evidence["no_longer_documents"])
        self.assertEqual(f.evidence["untouched"], "14 of 15")
        self.assertIn("shut the PC down", f.remediation)
        first = f.entity["state"]
        self.assertEqual(self.look()[1].entity["state"], first, "the same damage is the same state")
        Path(self.path(b, "png")).write_bytes(b"")
        f = self.look()[1]
        self.assertIn("in 2 places", f.title)
        self.assertNotEqual(f.entity["state"], first)
        self.assertEqual(canary.brief(canary.check())["changed"], 2)

    def test_a_decoy_swapped_for_another_file_is_ransomware(self):
        a = self.place()[0]
        target = self.path(a, "pdf")
        os.rename(target, target + ".locked")                                   # encrypted under a new name
        f = self.look()[1]
        self.assertEqual((f.rule, f.severity), ("canary.ransomware", "critical"))
        self.assertIn(os.path.basename(target) + ".locked", f.evidence["swapped_for_other_files"])
        self.assertNotIn("deleted", f.evidence)

    def test_the_decoy_beside_the_folder_is_the_first_file_and_is_watched_like_the_rest(self):
        a, b, c = self.place()
        with open(self.beside(a), "r+b") as f:                                   # rewritten where it stands
            f.write(os.urandom(a["beside"]["size"]))
        report, f = self.look()
        self.assertEqual((f.rule, report["folders"][0]["files"][-1]["state"]), ("canary.ransomware", "damaged"))
        self.assertIn(self.beside(a), f.evidence["no_longer_documents"])
        os.rename(self.beside(b), self.beside(b) + ".crypt")                     # rewritten under a new name
        report, f = self.look()
        self.assertIn(self.beside(b) + " (now " + b["beside"]["name"] + ".crypt)", f.evidence["swapped_for_other_files"])
        self.assertIn(self.beside(b) + ".crypt", f.evidence["new_files_beside_them"], "named with the folder it is really in")
        self.assertIn("in 2 places", f.title)
        os.rename(self.beside(b) + ".crypt", self.beside(b))
        os.remove(self.beside(a))
        os.remove(self.beside(c))                                                # simply deleted
        report, f = self.look()
        self.assertEqual((f.rule, len(f.evidence["deleted"].splitlines())), ("canary.destroyed", 2))
        self.assertEqual(canary.brief(report)["places"][2]["note"], "1 missing")

    def test_between_full_readings_a_decoy_is_read_only_if_its_size_or_time_moved(self):
        a = self.place()[0]
        target, seen = self.path(a, "docx"), {}
        self.assertEqual(d_canary.detect(canary.check(seen=seen)), [])
        self.assertEqual(len(seen), 15, "every decoy was read once and remembered")
        opened = []
        real_open = open
        with mock.patch("builtins.open", lambda path, *args, **kw: opened.append(path) or real_open(path, *args, **kw)):
            self.assertEqual(d_canary.detect(canary.check(seen=seen)), [])
        self.assertEqual([p for p in opened if str(p).startswith(self.work)], [], "nothing was opened the second time")
        Path(target).write_bytes(os.urandom(a["files"][0]["size"] + 7))          # what ransomware does: size or time moves
        self.assertEqual(d_canary.detect(canary.check(seen=seen))[0].rule, "canary.ransomware")
        self.assertNotIn(target, seen)
        # A rewrite that put back both the size and the time is only found when everything is read again.
        quiet, stamp = self.path(a, "png"), os.stat(self.path(a, "png"))
        Path(quiet).write_bytes(os.urandom(stamp.st_size))
        os.utime(quiet, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.assertEqual(canary.check(seen=seen)["summary"]["damaged"], 1)
        seen.clear()
        self.assertEqual(canary.check(seen=seen)["summary"]["damaged"], 2)
        self.assertEqual(canary.check()["summary"]["damaged"], 2, "a caller that remembers nothing reads everything")

    def test_a_ransom_note_beside_untouched_decoys_is_ransomware(self):
        a = self.place()[0]
        Path(a["path"], "HOW_TO_RESTORE_FILES.txt").write_text("pay up")
        f = self.look()[1]
        self.assertEqual(f.rule, "canary.ransomware")
        self.assertIn("HOW_TO_RESTORE_FILES.txt", f.evidence["ransom_note"])

    def test_deleting_decoys_is_destruction_but_not_called_ransomware(self):
        a, b, _c = self.place()
        os.remove(self.path(a, "png"))
        self.assertEqual(self.rule(), ("canary.destroyed", "high", "medium"))
        shutil.rmtree(b["path"])
        report, f = self.look()
        self.assertEqual((f.rule, f.severity), ("canary.destroyed", "high"))
        self.assertIn("in 2 places", f.title)
        self.assertEqual(len(f.evidence["deleted"].splitlines()), 5)
        self.assertEqual([fo["state"] for fo in report["folders"]], ["changed", "missing", "intact"])
        self.assertEqual(canary.brief(report)["places"][1]["note"], "the canary folder is gone")

    def test_an_editor_or_a_sync_service_is_not_ransomware(self):
        a = self.place()[0]
        target = self.path(a, "docx")
        Path(target).write_bytes(resaved(Path(target).read_bytes(), "word/document.xml"))
        f = self.look()[1]
        self.assertEqual((f.rule, f.severity, f.confidence), ("canary.edited", "medium", "low"))
        self.assertIn(target, f.evidence["edited_in_place"])
        Path(a["path"], "~$" + os.path.basename(target)).write_bytes(b"lock")    # what Word leaves while a file is open
        Path(a["path"], "desktop.ini").write_text("[.ShellClassInfo]")
        self.assertNotIn("new_files_beside_them", self.look()[1].evidence)
        Path(a["path"], "Budget-LAPTOP.xlsx").write_bytes(b"a sync conflict copy")
        f = self.look()[1]
        self.assertEqual(f.rule, "canary.edited")
        self.assertIn("Budget-LAPTOP.xlsx", f.evidence["new_files_beside_them"])

    def test_a_folder_that_is_not_there_is_not_an_alarm(self):
        a, b, c = self.place()
        shutil.move(self.roots[2], self.roots[2] + " (unplugged)")
        report, f = self.look()
        self.assertIsNone(f)
        self.assertEqual(report["folders"][2]["state"], "unavailable")
        self.assertEqual((canary.brief(report)["unread"], canary.brief(report)["changed"]), (5, 0))
        shutil.move(self.roots[2] + " (unplugged)", self.roots[2])
        self.assertEqual(self.look()[0]["folders"][2]["state"], "intact")
        record = canary.load()[0]
        record["folders"][0]["volume"] = (record["folders"][0]["volume"] or 0) + 1        # another disk now answers to that path
        canary._save(record)
        report, f = self.look()
        self.assertIsNone(f)
        self.assertEqual(report["folders"][0]["state"], "unavailable")

    @unittest.skipUnless(WINDOWS, "Windows access lists and marks")
    def test_permissions_marks_and_what_the_folder_above_hands_down(self):
        a, b, _c = self.place()
        target = self.path(a, "xlsx")
        icacls(target, "/grant", EVERYONE + ":F")
        f = self.look()[1]
        self.assertEqual((f.rule, f.severity, f.confidence, f.mitre), ("canary.permissions", "high", "medium", ["T1222.001"]))
        self.assertIn(target + ": permission added: allow Everyone full control", f.evidence["owner_or_permissions"])
        self.assertEqual(f.evidence["untouched"], "14 of 15")
        icacls(target, "/remove", EVERYONE)
        self.assertIsNone(self.look()[1], "back to who may do what: nothing to report")
        icacls(self.roots[1], "/grant", GUESTS + ":(OI)(CI)R")                    # the owner shares the folder above
        f = self.look()[1]
        self.assertEqual((f.rule, f.severity, f.confidence), ("canary.settings", "low", "low"))
        self.assertIn("handed down from the folder above", f.evidence["lesser_changes"])
        icacls(self.roots[1], "/remove", GUESTS)
        self.assertIsNone(self.look()[1])
        os.chmod(target, stat.S_IREAD)
        winapi.set_hidden(b["path"], False)
        f = self.look()[1]
        self.assertEqual(f.rule, "canary.settings")
        self.assertIn(target + ": it was marked Read-only", f.evidence["lesser_changes"])
        self.assertIn(b["path"] + ": its Hidden mark was cleared", f.evidence["lesser_changes"])
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
        winapi.set_hidden(b["path"])
        self.assertIsNone(self.look()[1])

    @unittest.skipUnless(WINDOWS, "Windows file locks and access lists")
    def test_in_use_is_unread_and_locked_out_is_a_permission_change(self):
        import msvcrt
        a = self.place()[0]
        target = self.path(a, "pdf")
        with open(target, "r+b") as held:
            msvcrt.locking(held.fileno(), msvcrt.LK_NBLCK, 4096)
            report, f = self.look()
            held.seek(0)
            msvcrt.locking(held.fileno(), msvcrt.LK_UNLCK, 4096)
        self.assertIsNone(f, "a file another program is using has not changed")
        self.assertEqual(report["summary"]["unread"], 1)
        self.assertEqual(canary.brief(report)["places"][0]["note"], "1 could not be read just now")
        alone = winapi._k32.CreateFileW(target, 0x80000000, 0, None, 3, 0, None)     # open for reading, sharing with nobody
        try:
            self.assertRaises(PermissionError, open, target, "rb")
            self.assertTrue(winapi.may_read(target), "refused because it is in use, not because of who is asking")
            report, f = self.look()
        finally:
            winapi._k32.CloseHandle(alone)
        self.assertEqual((f, report["summary"]["unread"], report["summary"]["locked"]), (None, 1, 0))
        icacls(target, "/deny", EVERYONE + ":(RD)")                              # nobody may read what is in it
        try:
            report, f = self.look()
        finally:
            icacls(target, "/remove:d", EVERYONE)
        self.assertEqual((report["summary"]["locked"], f.rule), (1, "canary.permissions"))
        self.assertIs(winapi.may_read(target), True)
        self.assertIn("Windows refuses to let HostGuard read it", f.evidence["owner_or_permissions"])
        self.assertIsNone(self.look()[1])

    def test_the_strongest_thing_names_the_finding_and_the_rest_is_evidence(self):
        a, b, c = self.place()
        Path(self.path(a, "docx")).write_bytes(resaved(Path(self.path(a, "docx")).read_bytes(), "word/document.xml"))
        self.assertEqual(self.rule()[0], "canary.edited")
        os.remove(self.path(b, "pdf"))
        self.assertEqual(self.rule()[0], "canary.destroyed")
        Path(self.path(c, "png")).write_bytes(os.urandom(900))
        f = self.look()[1]
        self.assertEqual(f.rule, "canary.ransomware")
        self.assertIn("in 1 place", f.title, "the title counts the places with the thing it names")
        for key in ("no_longer_documents", "deleted", "edited_in_place"):
            self.assertIn(key, f.evidence)

    def test_the_list_of_canaries_is_watched_too(self):
        self.place()
        remembered = canary.check()["manifest"]
        self.assertEqual(len(remembered["folders"]), 3)
        canary.manifest_path().write_bytes(os.urandom(300))                      # encrypted along with everything else
        report = canary.check()
        self.assertEqual((report["record"], report["folders"]), ("damaged", []))
        f = d_canary.detect(report)[0]
        self.assertEqual((f.rule, f.severity, f.title), ("canary.destroyed", "high", "HostGuard's list of its canaries was overwritten"))
        b = canary.brief(report)
        self.assertEqual((b["on"], b["record"]), (False, "damaged"))
        report = canary.check(remembered)                                        # the monitor still knows what it was watching
        self.assertEqual((report["record"], report["summary"]["untouched"]), ("damaged", 15))
        Path(self.path(remembered["folders"][0], "png")).write_bytes(os.urandom(50))
        f = d_canary.detect(canary.check(remembered))[0]
        self.assertEqual(f.rule, "canary.ransomware")
        self.assertIn("overwritten", f.evidence["the_record"])
        canary.manifest_path().unlink()
        report = canary.check(remembered)
        self.assertEqual(report["record"], "lost")
        self.assertIn("deleted while the monitor was running", d_canary.detect(report)[0].evidence["the_record"])
        self.assertEqual(canary.check()["record"], "none", "with nothing remembered, no list means no canaries")
        canary._save(remembered)

    def test_a_set_being_replaced_mid_check_is_not_an_alarm(self):
        self.place()
        real, calls = canary._check_folder, []

        def swapped_under_us(rec, seen=None):
            if not calls:
                calls.append(1)
                canary.remove()                     # the dashboard takes the set away while the monitor is half way through it
            return real(rec, seen)
        with mock.patch.object(canary, "_check_folder", swapped_under_us):
            report = canary.check()
        self.assertEqual((report["folders"], d_canary.detect(report)), ([], []))


canary_check = canary.check


def row(pid, name, path, mb=0.0, writes=0.0):
    return {"pid": pid, "name": name, "path": path, "created": 1700000000.0 + pid, "bytes_per_s": mb * 1048576, "writes_per_s": writes,
            "written_bytes": int(mb * 1048576 * 40)}


class Rules(unittest.TestCase):
    """The rules against hand-built reports."""

    def folder(self, n, files=("intact",) * 4, state="changed", strangers=(), changes=()):
        path = rf"C:\Users\a\Place{n}\!Archive abcd"
        return {"root": rf"C:\Users\a\Place{n}", "label": "x", "path": path, "state": state, "changes": list(changes),
                "strangers": [{"name": s, "bytes": 10, "twin_of": None, "note": "DECRYPT" in s} for s in strangers],
                "files": [{"name": f"f{i}.docx", "kind": "docx", "path": path + rf"\f{i}.docx", "state": s, "changes": [],
                           "was_bytes": 100, "now_bytes": 100, "starts_with": "00"} for i, s in enumerate(files)]}

    def judge(self, *folders, record="ok"):
        files = [f for fo in folders for f in fo["files"]]
        found = d_canary.detect({"record": record, "placed": 1700000000.0, "folders": list(folders),
                                 "summary": {"files": len(files), "folders": len(folders), "untouched": sum(f["state"] == "intact" for f in files)}})
        return (found[0].rule, found[0].severity) if found else None

    def test_what_fires_and_what_stays_quiet(self):
        quiet = self.folder(1, state="intact")
        self.assertIsNone(self.judge(quiet))
        self.assertIsNone(self.judge())
        self.assertIsNone(self.judge(record="none"))
        self.assertIsNone(self.judge(quiet, record="unread"), "a list that could not be opened just now says nothing")
        self.assertIsNone(self.judge(self.folder(1, ("unread",) * 4, state="intact")))
        self.assertIsNone(self.judge(self.folder(1, ("damaged",) * 4, state="unavailable")), "an unplugged drive is not judged at all")
        self.assertEqual(self.judge(self.folder(1, ("damaged", "intact", "intact", "intact"))), ("canary.ransomware", "critical"))
        self.assertEqual(self.judge(self.folder(1, ("missing",) * 4, strangers=("a.xyz",))), ("canary.ransomware", "critical"))
        self.assertEqual(self.judge(self.folder(1, strangers=("HOW_TO_DECRYPT.txt",))), ("canary.ransomware", "critical"))
        self.assertEqual(self.judge(self.folder(1, ("missing",) * 4, state="missing")), ("canary.destroyed", "high"))
        self.assertEqual(self.judge(self.folder(1, ("missing",) * 4, state="missing"), self.folder(2, ("missing",) * 4, state="missing")),
                         ("canary.destroyed", "high"), "decoys deleted everywhere are still not called ransomware")
        self.assertEqual(self.judge(self.folder(1, ("locked", "intact", "intact", "intact"))), ("canary.permissions", "high"))
        for kind in ("owner", "access", "encrypted"):
            self.assertEqual(self.judge(self.folder(1, changes=[{"kind": kind, "text": "x"}])), ("canary.permissions", "high"), kind)
        self.assertEqual(self.judge(self.folder(1, ("edited", "intact", "intact", "intact"))), ("canary.edited", "medium"))
        self.assertEqual(self.judge(self.folder(1, strangers=("notes.txt",))), ("canary.edited", "medium"))
        self.assertEqual(self.judge(quiet, record="lost"), ("canary.edited", "medium"))
        self.assertEqual(self.judge(quiet, record="damaged"), ("canary.destroyed", "high"))
        for kind in ("inherited", "attribute", "unread"):
            self.assertEqual(self.judge(self.folder(1, changes=[{"kind": kind, "text": "x"}])), ("canary.settings", "low"), kind)

    def test_a_writer_is_a_lead_only_when_it_is_heavy_and_untrusted(self):
        temp, ps = r"C:\Users\a\AppData\Local\Temp\enc.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        steam, tool = r"C:\Program Files (x86)\Steam\steam.exe", r"C:\Tools\sync.exe"
        sig_map = {temp.lower(): UNSIGNED, ps.lower(): MS, steam.lower(): VENDOR, tool.lower(): UNSIGNED,
                   r"c:\windows\explorer.exe": MS, r"c:\x\unknown.exe": {"status": "Unreadable", "signer": "", "issuer": "", "is_os": False}}
        rows = [row(10, "enc.exe", temp, mb=90, writes=4000), row(11, "steam.exe", steam, mb=40, writes=900),
                row(12, "powershell.exe", ps, mb=0.2, writes=600), row(13, "sync.exe", tool, mb=0.5, writes=20),
                row(14, "explorer.exe", r"C:\Windows\explorer.exe", mb=30), row(15, "unknown.exe", r"C:\x\unknown.exe", mb=30),
                row(16, "svchost.exe", "", mb=30)]
        text, found = d_canary.writers(rows, sig_map)
        self.assertEqual(len(text.splitlines()), 7, "every writer measured is shown as evidence")
        self.assertIn("enc.exe (pid 10): 90.0 MB a second in 4000 writes, not signed", text)
        self.assertEqual([(f.entity["pid"], f.severity, f.confidence) for f in found], [(10, "high", "medium"), (12, "high", "low")])
        first, second = found
        self.assertEqual((first.rule, first.category, first.entity["type"], first.entity["created"]), ("canary.writer", "process", "process", 1700000010.0))
        self.assertEqual((first.actions, second.actions), (["suspend", "kill", "quarantine"], ["suspend", "kill"]))
        self.assertIn("far more than any other", first.description)
        self.assertIn("lead, not proof", first.description)
        self.assertIn("script hosts", second.description)
        close = [row(10, "enc.exe", temp, mb=50), row(11, "steam.exe", steam, mb=40)]
        self.assertEqual([f.confidence for f in d_canary.writers(close, sig_map)[1]], ["low"], "not far ahead of the next one")
        many = [row(20 + i, f"e{i}.exe", temp, mb=50 - i) for i in range(5)]
        self.assertEqual(len(d_canary.writers(many, sig_map)[1]), 2)
        self.assertEqual(d_canary.writers([], {}), ("", []))


@unittest.skipUnless(WINDOWS, "the monitor reads Windows state")
class Monitoring(Placed):
    def setUp(self):
        super().setUp()
        self.store = Store(os.path.join(self.work, "monitor.db"))
        self.addCleanup(self.store.close)
        self.toasts = []
        patch = mock.patch.object(notify, "toast", lambda title, text: self.toasts.append((title, text)) or True)
        patch.start()
        self.addCleanup(patch.stop)
        self.mon = monitor.Monitor(store=self.store)
        self.mon._disk_writers = lambda seconds=1.0: []

    def findings(self, *statuses):
        return [(f["rule"], f["status"]) for f in self.store.findings(statuses or None) if f["collector"] == "canaries"]

    def test_raised_once_kept_while_true_and_closed_when_replaced(self):
        folders = self.place()
        self.mon.watch_canaries()
        self.assertEqual((self.findings(), self.toasts), ([], []))
        self.assertGreater(self.mon.canary_checked, time.time() - 5)
        Path(self.path(folders[0], "docx")).write_bytes(os.urandom(3000))
        self.mon.watch_canaries()
        self.assertEqual(self.findings(), [("canary.ransomware", OPEN)])
        self.assertEqual(len(self.toasts), 1)
        self.assertEqual(self.toasts[0][0], "HostGuard: critical")
        self.assertIn("Canary tripped", self.toasts[0][1])
        for _ in range(3):
            self.mon.watch_canaries()
        self.assertEqual((self.findings(), len(self.toasts)), ([("canary.ransomware", OPEN)], 1), "one alarm, not one every five seconds")
        self.assertEqual(self.store.actions(state="pending"), [], "there is nothing to contain in a canary itself")
        canary.place()
        self.mon.watch_canaries()
        self.assertEqual(self.findings(), [("canary.ransomware", GONE)])
        self.assertEqual(len(self.toasts), 1)

    def test_dealt_with_sticks_until_something_else_happens(self):
        folders = self.place()
        os.remove(self.path(folders[0], "png"))
        self.mon.watch_canaries()
        fid = self.store.findings((OPEN,))[0]["id"]
        self.store.set_status(fid, RESOLVED, "I deleted that one myself")
        for _ in range(2):
            self.mon.watch_canaries()
        self.assertEqual((self.findings(), len(self.toasts)), ([("canary.destroyed", RESOLVED)], 1))
        os.remove(self.path(folders[1], "png"))
        self.mon.watch_canaries()
        self.assertEqual((self.findings(), len(self.toasts)), ([("canary.destroyed", OPEN)], 2), "more went missing: that is news")

    def test_a_stronger_sign_replaces_a_weaker_finding(self):
        folders = self.place()
        Path(folders[0]["path"], "notes.txt").write_text("hello")
        self.mon.watch_canaries()
        self.assertEqual(self.findings(), [("canary.edited", OPEN)])
        Path(self.path(folders[1], "xlsx")).write_bytes(os.urandom(100))
        self.mon.watch_canaries()
        self.assertEqual(sorted(self.findings()), [("canary.edited", GONE), ("canary.ransomware", OPEN)])
        self.assertEqual([t[0] for t in self.toasts], ["HostGuard", "HostGuard: critical"])
        again = monitor.Monitor(store=self.store)           # a monitor started later takes over the open finding
        again._disk_writers = lambda seconds=1.0: []
        again.canary_open = {f["id"] for f in self.store.findings((OPEN,)) if f["collector"] == "canaries"}
        canary.remove()
        again.watch_canaries()
        self.assertEqual(sorted(self.findings()), [("canary.edited", GONE), ("canary.ransomware", GONE)])

    def test_the_program_writing_most_becomes_a_request_to_suspend_it(self):
        folders = self.place()
        exe = os.path.join(self.work, "enc.exe")
        rows = [row(4242, "enc.exe", exe, mb=120, writes=5000), row(4243, "steam.exe", r"C:\Program Files (x86)\Steam\steam.exe", mb=3)]
        measured = []
        self.mon._disk_writers = lambda seconds=1.0: measured.append(1) or rows
        with mock.patch.object(monitor.sigs, "check", return_value={exe.lower(): UNSIGNED}):
            Path(self.path(folders[0], "pdf")).write_bytes(os.urandom(500))
            self.mon.watch_canaries()
            self.mon.watch_canaries()
            self.assertEqual(len(measured), 1, "measured when the damage is first seen, not on every pass")
            Path(self.path(folders[1], "pdf")).write_bytes(os.urandom(500))
            self.mon.watch_canaries()
            self.assertEqual(len(measured), 2, "and again when it spreads")
        found = {f["rule"]: f for f in self.store.findings((OPEN,))}
        self.assertEqual(sorted(found), ["canary.ransomware", "canary.writer"])
        self.assertIn("enc.exe (pid 4242): 120.0 MB a second", found["canary.ransomware"]["evidence"]["writing_most_when_noticed"])
        lead = found["canary.writer"]
        self.assertEqual((lead["kind"], lead["severity"], lead["confidence"], lead["entity"]["pid"]), ("event", "high", "medium", 4242))
        pending = self.store.actions(state="pending")
        self.assertEqual([(p["action"], p["target"]["pid"], p["finding_id"]) for p in pending], [("suspend", 4242, lead["id"])])
        self.assertTrue(any("Waiting for your approval" in text for _title, text in self.toasts))

    def test_the_alarm_sounds_even_when_it_cannot_be_recorded(self):
        folders = self.place()
        Path(self.path(folders[0], "png")).write_bytes(os.urandom(64))

        def database_is_gone(*_a, **_k):
            raise OSError("database disk image is malformed")
        self.mon._emit = database_is_gone
        for _ in range(3):
            with self.assertRaises(OSError):
                self.mon.watch_canaries()
        self.assertEqual(len(self.toasts), 1)
        self.assertEqual(self.toasts[0][0], "HostGuard: critical")
        self.assertIn("could not record this", self.toasts[0][1])

    def test_the_monitor_remembers_the_list_if_the_list_is_destroyed(self):
        folders = self.place()
        self.mon.watch_canaries()
        canary.manifest_path().unlink()
        self.mon.watch_canaries()
        self.assertEqual(self.findings(), [("canary.edited", OPEN)])
        Path(self.path(folders[2], "docx")).write_bytes(os.urandom(64))
        self.mon.watch_canaries()
        self.assertIn(("canary.ransomware", OPEN), self.findings())
        canary._save(self.mon.canary_record)

    def test_the_step_loop_runs_the_canary_check_and_reports_when(self):
        self.assertEqual(paths.DEFAULTS["monitor"]["canary_interval_s"], 3)
        self.assertIn('("canaries", m.get("canary_interval_s", 3), self.watch_canaries)', Path(monitor.__file__).read_text(encoding="utf-8"))
        self.place()
        self.mon.watch_canaries()
        self.assertEqual(len(self.mon.canary_seen), 15)
        self.mon.canary_read_all = time.time() - 31         # half a minute on, everything is read afresh
        with mock.patch.object(canary, "check", side_effect=lambda remembered, seen: self.assertEqual(seen, {}) or canary_check(remembered, seen)):
            self.mon.watch_canaries()
        self.assertEqual(len(self.mon.canary_seen), 15)
        self.mon._heartbeat()
        self.addCleanup(lambda: monitor.state_path().unlink(missing_ok=True))
        self.assertAlmostEqual(monitor.status()["canary_checked"], self.mon.canary_checked, places=3)

    def test_who_is_writing_is_measured_from_windows_counters(self):
        target = os.path.join(self.work, "busy.bin")
        code = ("import sys, time\nblock = b'x' * (1 << 20)\nend = time.time() + 15\n"
                "with open(sys.argv[1], 'wb', buffering=0) as f:\n    while time.time() < end:\n        f.seek(0)\n        f.write(block)\n")
        child = subprocess.Popen([sys.executable, "-c", code, target], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            time.sleep(1.5)
            rows = monitor.Monitor(store=self.store)._disk_writers(1.0)
        finally:
            child.kill()
            child.wait(10)
        mine = [r for r in rows if r["pid"] == child.pid]
        self.assertTrue(mine, [(r["name"], round(r["bytes_per_s"])) for r in rows])
        self.assertGreater(mine[0]["bytes_per_s"], 1 << 20)
        self.assertGreater(mine[0]["writes_per_s"], 1)
        self.assertTrue(mine[0]["path"].lower().endswith(".exe") and mine[0]["created"])
        self.assertNotIn(os.getpid(), [r["pid"] for r in rows], "HostGuard does not measure itself")
        self.assertIsNone(winapi.io_counters(0), "a process that cannot be opened has no counters to read")
        self.assertGreaterEqual(winapi.io_counters(os.getpid())["written_bytes"], 0)
        self.assertTrue(all(len(d) == 3 and d.endswith(":\\") for d in winapi.fixed_drives()) and winapi.fixed_drives())


@unittest.skipUnless(WINDOWS, "the dashboard and the scan read Windows state")
class Requests(Placed):
    def wait(self, api, task_id):
        deadline = time.time() + 60
        while time.time() < deadline:
            task = next(t for t in api.tasks.snapshot() if t["id"] == task_id)
            if task["state"] != "running":
                return task
            time.sleep(0.05)
        self.fail("the task did not finish")

    def test_the_dashboard_switch_places_reads_back_and_removes(self):
        from hostguard import api as api_mod
        api = api_mod.Api()
        off = api._canaries()
        self.assertEqual((off["on"], off["files"], off["alarm"], [p["root"] for p in off["plan"]]), (False, 0, None, self.roots))
        for bad in ({}, {"on": "yes"}, {"on": 1}, {"what": "place"}):
            with self.assertRaises(api_mod.ApiError):
                api.post("canary", bad)
        task = self.wait(api, api.post("canary", {"on": True})["task"])
        self.assertEqual((task["state"], task["title"]), ("done", "Place canary files"))
        self.assertEqual(sum("placed " in line for line in task["log"]), 4, task["log"])
        on = api._canaries()
        self.assertEqual((on["on"], on["folders"], on["files"], on["untouched"], on["changed"], on["alarm"]), (True, 3, 15, 15, 0, None))
        target = os.path.join(on["places"][0]["path"], os.listdir(on["places"][0]["path"])[0])
        Path(target).write_bytes(os.urandom(200))
        tripped = api._canaries()
        self.assertEqual((tripped["changed"], tripped["folders_changed"], tripped["alarm"]["rule"], tripped["alarm"]["severity"]),
                         (1, 1, "canary.ransomware", "critical"))
        self.assertEqual(tripped["places"][0]["note"], "1 no longer a document")
        json.dumps(tripped)
        task = self.wait(api, api.post("canary", {"on": False})["task"])
        self.assertEqual(task["state"], "done")
        self.assertIn("left 1 that had been changed", task["log"][-1])
        self.assertFalse(api._canaries()["on"])
        store = Store()
        try:
            logged = [(a["action"], a["ok"], a["target"]["type"]) for a in store.actions(limit=5) if a["action"].startswith("canary:")]
        finally:
            store.close()
        self.assertEqual(logged[:2], [("canary:remove", 1, "canary"), ("canary:place", 1, "canary")], "newest first")

    def test_the_command_does_what_the_switch_does(self):
        def run(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(["canary", *args])
            return code, out.getvalue()
        code, text = run()
        self.assertEqual(code, 0)
        self.assertIn("not placed", text)
        code, text = run("on")
        self.assertEqual(code, 0)
        self.assertIn(self.roots[0] + "  (set by HOSTGUARD_CANARY_ROOTS)", text)
        self.assertIn("OK: placed 15 canary files in 3 place(s)", text)
        code, text = run("status")
        self.assertEqual(code, 0)
        self.assertIn("Canary files: 15 in 3 place(s)", text)
        self.assertIn("none changed", text)
        folder = canary.load()[0]["folders"][1]
        os.remove(self.path(folder, "docx"))
        code, text = run("status")
        self.assertEqual(code, 1, "a tripped canary is an exit code a script can act on")
        self.assertIn("1 CHANGED in 1 place(s)", text)
        self.assertIn("high: Canary tripped: decoy documents were deleted in 1 place", text)
        code, text = run("status", "--json")
        data = json.loads(text)
        self.assertEqual((data["changed"], data["finding"]["rule"], len(data["detail"])), (1, "canary.destroyed", 3))
        self.assertNotIn("manifest", data)
        self.assertEqual(run("replace")[0], 0)
        self.assertEqual(run("status")[0], 0)
        code, text = run("off")
        self.assertEqual(code, 0)
        self.assertIn("OK: removed 15 canary file(s)", text)

    def test_a_scan_checks_the_canaries_too(self):
        store = Store(os.path.join(self.work, "scan.db"))
        self.addCleanup(store.close)
        cfg = json.loads(json.dumps(paths.DEFAULTS))
        cfg["scan"]["defender_ondemand"] = False
        nothing = [mock.patch.object(scan.winapi, "list_processes", return_value=[]), mock.patch.object(scan.winapi, "connections", return_value=[]),
                   mock.patch.object(scan.c_persist, "collect", return_value={"entries": [], "gaps": []}),
                   mock.patch.object(scan.c_system, "collect", return_value={}),
                   mock.patch.object(scan.c_events, "collect", return_value={"events": {}, "coverage": {}, "gaps": []}),
                   mock.patch.object(scan.c_files, "collect", return_value={"files": []}),
                   mock.patch.object(scan.d_browsers, "collect", return_value={"extensions": []}),
                   mock.patch.object(scan.d_memory, "collect", return_value={"results": []}),
                   mock.patch.object(scan.sigs, "check", return_value={})]

        def run_scan():
            lines = []
            with contextlib.ExitStack() as stack:
                for patch in nothing:
                    stack.enter_context(patch)
                summary = scan.run("quick", store, cfg=cfg, log=lines.append)
            return summary, lines, [(f["rule"], f["status"]) for f in store.findings(None) if f["collector"] == "canaries"]

        summary, lines, found = run_scan()
        usual = summary["verdict"]["level"]                 # whatever an empty PC looks like to the other rules
        self.assertEqual((found, summary["coverage"]["canary_files"]), ([], 0))
        self.assertFalse(any(line.startswith("canaries:") for line in lines), "no canaries placed, nothing to say")
        folders = self.place()
        summary, lines, found = run_scan()
        self.assertEqual((found, summary["coverage"]["canary_files"]), ([], 15))
        self.assertIn("canaries: 15 of 15 decoy documents untouched in 3 place(s)", lines)
        Path(self.path(folders[0], "xlsx")).write_bytes(os.urandom(256))
        summary, lines, found = run_scan()
        self.assertEqual(found, [("canary.ransomware", OPEN)])
        self.assertEqual(summary["verdict"]["level"], "compromised")
        fid = store.findings((OPEN,))[0]["id"]
        store.set_status(fid, RESOLVED, "restored from backup")
        self.assertEqual(run_scan()[2], [("canary.ransomware", RESOLVED)], "dealt with stays dealt with while nothing else changes")
        store.set_status(fid, OPEN)
        canary.place()
        summary, lines, found = run_scan()
        self.assertEqual(found, [("canary.ransomware", GONE)])
        self.assertEqual(summary["verdict"]["level"], usual)

    def test_the_settings_are_ones_the_config_command_accepts(self):
        self.addCleanup(lambda: paths.save_config(paths.DEFAULTS))
        self.assertFalse(paths.set_value("canary.drive_roots", "off")["canary"]["drive_roots"])
        self.assertEqual(paths.set_value("canary.extra_dirs", r"D:\Photos; E:\Work")["canary"]["extra_dirs"], [r"D:\Photos", r"E:\Work"])
        self.assertEqual(paths.set_value("monitor.canary_interval_s", "10")["monitor"]["canary_interval_s"], 10)
        with self.assertRaises(ValueError):
            paths.set_value("canary.drive_roots", "sometimes")


@unittest.skipUnless(WINDOWS, "Windows access lists")
class WindowsFiles(unittest.TestCase):
    def test_owner_and_access_list_are_read_as_text_and_a_folder_can_be_hidden(self):
        folder = tempfile.mkdtemp(prefix="sec-", dir=_TMP)
        target = os.path.join(folder, "a.txt")
        Path(target).write_text("x")
        before = winapi.file_security(target)
        parts = canary.split_security(before)
        self.assertTrue(before.startswith("O:") and "D:" in before)
        self.assertTrue(parts["owner"] and parts["handed_down"] and not parts["own"] and not parts["protected"], "a new file takes everything from its folder")
        icacls(target, "/grant", EVERYONE + ":R")
        after = canary.split_security(winapi.file_security(target))
        self.assertEqual((len(after["own"]), after["handed_down"], after["owner"]), (1, parts["handed_down"], parts["owner"]))
        self.assertIsNone(winapi.file_security(os.path.join(folder, "not there")))
        self.assertTrue(winapi.set_hidden(folder))
        self.assertTrue(os.stat(folder).st_file_attributes & winapi.FILE_ATTRIBUTE_HIDDEN)
        self.assertTrue(winapi.set_hidden(folder, False))
        self.assertFalse(os.stat(folder).st_file_attributes & winapi.FILE_ATTRIBUTE_HIDDEN)
        self.assertFalse(winapi.set_hidden(os.path.join(folder, "not there")))


if __name__ == "__main__":
    unittest.main()
