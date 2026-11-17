"""The add-on downloader: what it may fetch, what it refuses, and that a bad download installs nothing.

No test touches the internet. A stand-in plays GitHub and hands back whatever bytes a test wants.
"""

import hashlib
import io
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-addons-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import addons, components  # noqa: E402

BASE = "https://github.com/example/tool/releases/download/v1/"


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


def zipped(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def pinned(name: str, data: bytes, kind: str, into: str = "") -> dict:
    return {"name": name, "kind": kind, "into": into, "size": len(data), "url": BASE + name, "sha256": hashlib.sha256(data).hexdigest()}


class Source:
    """Plays GitHub: a table of address to bytes, and a record of what was asked for."""

    def __init__(self, files: dict):
        self.files, self.asked = files, []

    def __call__(self, url: str):
        self.asked.append(url)
        if url not in self.files:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return io.BytesIO(self.files[url])


YARA_ZIP = zipped({"yara64.exe": b"MZ yara", "yarac64.exe": b"MZ yarac"})
RULES_ZIP = zipped({"packages/core/yara-rules-core.yar": b"rule a { condition: true }", "packages/core/README.md": b"notes"})
HOLLOWS = b"MZ hollows hunter"
YARA_PINS = {"yara": {"version": "1.0 test", "files": [pinned("yara-win64.zip", YARA_ZIP, "zip"), pinned("rules-core.zip", RULES_ZIP, "rules", "rules")]}}
HOLLOWS_PINS = {"hollows_hunter": {"version": "9.9", "files": [pinned("hollows_hunter64.exe", HOLLOWS, "file")]}}


class Fresh(unittest.TestCase):
    def setUp(self):
        self.tools = Path(components.tools_dir())
        for child in self.tools.iterdir():
            shutil.rmtree(child) if child.is_dir() else child.unlink()

    def assertNothingInstalled(self):
        self.assertEqual(sorted(p.name for p in self.tools.iterdir()), [], "no folder, no leftovers")


class Pins(unittest.TestCase):
    def test_every_pin_is_an_exact_release_file(self):
        known = {c["id"] for c in components.CATALOG}
        self.assertEqual(set(addons.PINS), known, "every add-on HostGuard can use can be downloaded, and nothing else")
        for addon_id, pin in addons.PINS.items():
            self.assertTrue(pin["version"] and pin["files"])
            for f in pin["files"]:
                self.assertRegex(f["sha256"], r"^[0-9a-f]{64}$", f["name"])
                self.assertGreater(f["size"], 1000)
                self.assertIn(f["kind"], ("zip", "rules", "file"))
                self.assertEqual(os.path.basename(f["name"]), f["name"])
                self.assertRegex(f["url"], r"^https://github\.com/[\w.-]+/[\w.-]+/releases/download/[\w.-]+/" + re.escape(f["name"]) + "$")
                self.assertEqual(addons.check_url(f["url"]), f["url"])
                self.assertNotIn("latest", f["url"], "a pin names one release, never whatever is newest")
            plan = addons.plan(addon_id)
            self.assertEqual(plan["bytes"], sum(f["size"] for f in pin["files"]))
            self.assertTrue(all(f["source"].startswith("github.com/") and f["size_text"] for f in plan["files"]))
        self.assertIsNone(addons.plan("sysmon"))
        self.assertIsNone(addons.plan("nope"))

    def test_only_github_over_https(self):
        for good in ("https://github.com/a/b/releases/download/v1/x.zip", "https://objects.githubusercontent.com/x?y=1",
                     "https://release-assets.githubusercontent.com/x", "https://GitHub.com:443/a/b"):
            self.assertEqual(addons.check_url(good), good)
        for bad in ("http://github.com/a/b/releases/download/v1/x.zip", "https://github.com.evil.example/a", "https://evil.example/github.com/a",
                    "https://user:pw@github.com/a", "https://github.com@evil.example/a", "https://github.com:8443/a",
                    "https://raw.githubusercontent.com/a/b/main/x", "https://gist.github.com/a", "ftp://github.com/a", "file:///C:/Windows/win.ini",
                    "//github.com/a", "github.com/a", "", "https://[bad", "https://127.0.0.1/a"):
            with self.assertRaises(addons.Refused, msg=bad):
                addons.check_url(bad)

    def test_a_redirect_is_followed_only_to_github(self):
        handler = addons._OnlyGitHub()
        req = urllib.request.Request(BASE + "x.zip")
        onward = handler.redirect_request(req, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/abc?sig=1")
        self.assertEqual(onward.full_url, "https://release-assets.githubusercontent.com/abc?sig=1")
        for elsewhere in ("https://evil.example/x.zip", "http://github.com/a/b/x.zip", "https://github.com.evil.example/x"):
            with self.assertRaises(addons.Refused):
                handler.redirect_request(req, None, 302, "Found", {}, elsewhere)


class Install(Fresh):
    def test_a_verified_archive_is_unpacked_where_scans_look(self):
        source, log = Source({BASE + "yara-win64.zip": YARA_ZIP, BASE + "rules-core.zip": RULES_ZIP}), []
        res = addons.install("yara", log=log.append, open_url=source, pins=YARA_PINS)
        self.assertTrue(res["ok"], res)
        self.assertEqual(source.asked, [BASE + "yara-win64.zip", BASE + "rules-core.zip"])
        self.assertEqual(Path(components.find("yara")).read_bytes(), b"MZ yara")
        rules = components.yara_rules()
        self.assertEqual([os.path.basename(r) for r in rules], ["yara-rules-core.yar"], "rule files only, flattened into rules")
        self.assertFalse(list(self.tools.rglob("README.md")))
        self.assertEqual(addons.installed_info("yara")["version"], "1.0 test")
        self.assertTrue(next(r for r in components.status() if r["id"] == "yara")["installed"])
        self.assertEqual(sorted(p.name for p in self.tools.iterdir()), ["yara"], "the staging folder is gone")
        self.assertTrue(any("SHA-256 match" in line for line in log))

    def test_a_single_program_is_stored_as_it_is(self):
        res = addons.install("hollows_hunter", open_url=Source({BASE + "hollows_hunter64.exe": HOLLOWS}), pins=HOLLOWS_PINS)
        self.assertTrue(res["ok"], res)
        self.assertEqual(Path(components.find("hollows_hunter")).read_bytes(), HOLLOWS)

    def test_a_file_that_differs_from_its_pin_installs_nothing(self):
        same_length = bytes(reversed(YARA_ZIP))
        for served, expect in ((same_length, "SHA-256"), (YARA_ZIP + b"extra", "larger"), (YARA_ZIP[:-9], "bytes"), (b"", "bytes")):
            res = addons.install("yara", open_url=Source({BASE + "yara-win64.zip": served, BASE + "rules-core.zip": RULES_ZIP}), pins=YARA_PINS)
            self.assertFalse(res["ok"], res)
            self.assertIn("nothing was installed", res["message"])
            self.assertIn(expect, res["message"])
            self.assertNothingInstalled()

    def test_a_bad_second_file_leaves_the_first_uninstalled_too(self):
        res = addons.install("yara", open_url=Source({BASE + "yara-win64.zip": YARA_ZIP, BASE + "rules-core.zip": b"x" * len(RULES_ZIP)}), pins=YARA_PINS)
        self.assertFalse(res["ok"], res)
        self.assertNothingInstalled()

    def test_an_archive_cannot_write_outside_its_folder(self):
        outside = self.tools.parent / "escaped.txt"
        for name in ("../escaped.txt", "../../escaped.txt", "a/../../escaped.txt", "/escaped.txt", "C:/escaped.txt", "sub\\..\\..\\escaped.txt",
                     "..\\escaped.txt", "nul", "con.txt", "ok/trailing. ", "a:b"):
            evil = zipped({"yara64.exe": b"MZ", name: b"gotcha"})
            pins = {"yara": {"version": "evil", "files": [pinned("yara-win64.zip", evil, "zip")]}}
            res = addons.install("yara", open_url=Source({BASE + "yara-win64.zip": evil}), pins=pins)
            self.assertFalse(res["ok"], name)
            self.assertIn("unsafe path", res["message"], name)
            self.assertNothingInstalled()
            self.assertFalse(outside.exists(), name)
            self.assertFalse((self.tools.parent.parent / "escaped.txt").exists(), name)

    def test_oversized_archives_are_refused(self):
        many = zipped({f"f{i}.txt": b"x" for i in range(6)} | {"yara64.exe": b"MZ"})
        big = zipped({"yara64.exe": b"MZ" + bytes(5000)})
        real = (addons.MAX_FILES, addons.MAX_UNPACKED)
        try:
            addons.MAX_FILES = 4
            pins = {"yara": {"version": "t", "files": [pinned("a.zip", many, "zip")]}}
            self.assertIn("entries", addons.install("yara", open_url=Source({BASE + "a.zip": many}), pins=pins)["message"])
            addons.MAX_FILES, addons.MAX_UNPACKED = real[0], 1000
            pins = {"yara": {"version": "t", "files": [pinned("b.zip", big, "zip")]}}
            self.assertIn("600 MB", addons.install("yara", open_url=Source({BASE + "b.zip": big}), pins=pins)["message"])
        finally:
            addons.MAX_FILES, addons.MAX_UNPACKED = real
        self.assertNothingInstalled()

    def test_not_an_archive_and_an_empty_one(self):
        junk = b"this is not a zip file at all"
        pins = {"yara": {"version": "t", "files": [pinned("a.zip", junk, "zip")]}}
        self.assertIn("not a readable archive", addons.install("yara", open_url=Source({BASE + "a.zip": junk}), pins=pins)["message"])
        no_rules = zipped({"README.md": b"no rules in here"})
        pins = {"yara": {"version": "t", "files": [pinned("yara-win64.zip", YARA_ZIP, "zip"), pinned("r.zip", no_rules, "rules", "rules")]}}
        res = addons.install("yara", open_url=Source({BASE + "yara-win64.zip": YARA_ZIP, BASE + "r.zip": no_rules}), pins=pins)
        self.assertIn("none of the expected files", res["message"])
        self.assertNothingInstalled()

    def test_what_you_already_keep_there_stays(self):
        mine = self.tools / "yara" / "rules" / "mine.yar"
        mine.parent.mkdir(parents=True)
        mine.write_text("rule mine { condition: false }")
        (self.tools / "yara" / "notes.txt").write_text("keep me")
        res = addons.install("yara", open_url=Source({BASE + "yara-win64.zip": YARA_ZIP, BASE + "rules-core.zip": RULES_ZIP}), pins=YARA_PINS)
        self.assertTrue(res["ok"], res)
        self.assertEqual(mine.read_text(), "rule mine { condition: false }")
        self.assertEqual((self.tools / "yara" / "notes.txt").read_text(), "keep me")
        self.assertEqual(sorted(os.path.basename(r) for r in components.yara_rules()), ["mine.yar", "yara-rules-core.yar"])

    def test_a_vanished_release_and_no_network_are_said_plainly(self):
        res = addons.install("yara", open_url=Source({}), pins=YARA_PINS)
        self.assertEqual((res["ok"], "no longer published" in res["message"]), (False, True), res)

        def offline(url):
            raise urllib.error.URLError("no route to host")
        res = addons.install("yara", open_url=offline, pins=YARA_PINS)
        self.assertEqual((res["ok"], "download failed" in res["message"]), (False, True), res)

        def refused(url):
            return addons._open("https://evil.example/" + url.rsplit("/", 1)[1])
        res = addons.install("yara", open_url=refused, pins=YARA_PINS)
        self.assertIn("only GitHub", res["message"])
        self.assertNothingInstalled()

    def test_a_program_that_is_not_there_afterwards_is_reported(self):
        only_rules = zipped({"rules/sigma/a.yml": b"title: a"})
        pins = {"hayabusa": {"version": "t", "files": [pinned("h.zip", only_rules, "zip")]}}
        res = addons.install("hayabusa", open_url=Source({BASE + "h.zip": only_rules}), pins=pins)
        self.assertFalse(res["ok"], res)
        self.assertIn("Defender may have removed it", res["message"])

    def test_unknown_names(self):
        self.assertFalse(addons.install("sysmon", open_url=Source({}))["ok"])
        self.assertFalse(addons.install("../yara", open_url=Source({}))["ok"])
        self.assertFalse(addons.remove("../yara")["ok"])
        self.assertFalse(addons.remove("nope")["ok"])

    def test_remove_takes_the_folder_away(self):
        addons.install("hollows_hunter", open_url=Source({BASE + "hollows_hunter64.exe": HOLLOWS}), pins=HOLLOWS_PINS)
        keep = self.tools / "yara"
        keep.mkdir()
        res = addons.remove("hollows_hunter")
        self.assertTrue(res["ok"], res)
        self.assertFalse((self.tools / "hollows_hunter").exists())
        self.assertTrue(keep.is_dir(), "only the named add-on goes")
        self.assertIsNone(components.find("hollows_hunter"))
        self.assertEqual(addons.remove("hollows_hunter")["message"], "Hollows Hunter is not installed")


@unittest.skipUnless(WINDOWS, "the dashboard's request layer reads Windows state")
class Requests(Fresh):
    @classmethod
    def setUpClass(cls):
        from hostguard import api
        cls.api_mod, cls.api = api, api.Api()

    def wait(self, task_id):
        deadline = time.time() + 30
        while time.time() < deadline:
            task = next(t for t in self.api.tasks.snapshot() if t["id"] == task_id)
            if task["state"] != "running":
                return task
            time.sleep(0.05)
        self.fail("the task did not finish")

    def test_rows_say_what_a_download_would_fetch(self):
        rows = {r["id"]: r for r in self.api._addons()}
        self.assertEqual(rows["yara"]["download"]["files"][0]["name"], addons.PINS["yara"]["files"][0]["name"])
        self.assertTrue(rows["yara"]["folder"].endswith(os.path.join("tools", "yara")))
        self.assertIsNone(rows["sysmon"]["download"], "Sysmon is a Windows feature, switched on under Hardening")
        self.assertIsNone(rows["yara"]["managed_version"])

    def test_only_known_add_ons_and_actions(self):
        for body in ({"id": "nope", "what": "install"}, {"id": "sysmon", "what": "install"}, {"id": "yara", "what": "explode"},
                     {"id": ["yara"], "what": "install"}, {"id": "../yara", "what": "remove"}, {"what": "install"}, {}):
            with self.assertRaises(self.api_mod.ApiError, msg=str(body)):
                self.api.post("addon", body)

    def test_a_download_runs_as_one_background_task(self):
        gate, calls = threading.Event(), []
        real = (addons.install, addons.remove)

        def slow_install(addon_id, log=None, **kw):
            calls.append(("install", addon_id))
            log("Downloading the stand-in")
            gate.wait(20)
            return {"ok": True, "message": "stand-in installed"}
        addons.install = slow_install
        addons.remove = lambda addon_id: calls.append(("remove", addon_id)) or {"ok": True, "message": "stand-in removed"}
        try:
            first = self.api.post("addon", {"id": "yara", "what": "install"})
            self.assertIn("Download YARA", first["message"])
            with self.assertRaises(self.api_mod.ApiError):
                self.api.post("addon", {"id": "hayabusa", "what": "install"})       # one at a time
            gate.set()
            done = self.wait(first["task"])
            self.assertEqual((done["state"], done["log"][-1]), ("done", "Done: stand-in installed"))
            self.assertEqual(self.wait(self.api.post("addon", {"id": "yara", "what": "remove"})["task"])["state"], "done")
            self.assertEqual(calls, [("install", "yara"), ("remove", "yara")])
        finally:
            gate.set()
            addons.install, addons.remove = real


if __name__ == "__main__":
    unittest.main()
