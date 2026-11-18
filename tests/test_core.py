"""Storage, helpers, add-on parsers, the scan's bookkeeping and the requests behind the dashboard."""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-core-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import components, lnk, paths, report, scan, util  # noqa: E402
from hostguard.model import Finding  # noqa: E402
from hostguard.store import EVENT_TTL_DAYS, Store  # noqa: E402

VENDOR = {"status": "Valid", "signer": "CN=Example Software Ltd", "issuer": "", "is_os": False}
UNSIGNED = {"status": "NotSigned", "signer": "", "issuer": "", "is_os": False}


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    for k in ("HOSTGUARD_YARA", "HOSTGUARD_YARA_RULES", "HOSTGUARD_HOLLOWS_HUNTER"):
        os.environ.pop(k, None)
    shutil.rmtree(_TMP, ignore_errors=True)


def fresh_store() -> Store:
    return Store(os.path.join(_TMP, f"db-{time.time_ns()}.db"))


def finding(name="a", severity="high", kind="state", collector="processes", category="process", **kw) -> Finding:
    return Finding(rule="test." + name, title="Finding " + name, severity=severity, category=category, kind=kind, collector=collector,
                   key_parts=(name,), entity=kw.pop("entity", {}), actions=kw.pop("actions", []), **kw)


class StoreLifecycle(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        self.addCleanup(self.store.close)

    def scan(self, findings, collectors=("processes",)):
        run = self.store.start_run("quick", False)
        change = self.store.upsert_findings(run, [f.to_row() for f in findings], list(collectors))
        self.store.end_run(run, {"ran": list(collectors)}, {"verdict": {}})
        return change

    def status(self, f):
        return self.store.get_finding(f.key)["status"]

    def test_seen_gone_and_back_again(self):
        a, b = finding("a"), finding("b")
        self.assertEqual(sorted(self.scan([a, b])["new"]), sorted([a.key, b.key]))
        self.assertEqual(self.scan([a])["new"], [])
        self.assertEqual((self.status(a), self.status(b)), ("open", "gone"))
        self.assertEqual(self.scan([a, b])["reopened"], [b.key])
        self.assertEqual(self.status(b), "open")
        self.assertEqual(self.store.get_finding(a.key)["seen_count"], 3)

    def test_a_collector_that_did_not_run_marks_nothing_gone(self):
        a = finding("a", collector="files")
        self.scan([a], collectors=("files",))
        self.scan([], collectors=("processes",))
        self.assertEqual(self.status(a), "open")

    def test_dispositions_survive_rescans(self):
        allowed, resolved, event = finding("allowed"), finding("resolved"), finding("event", kind="event", collector="eventlogs")
        self.scan([allowed, resolved, event], collectors=("processes", "eventlogs"))
        self.store.set_status(allowed.key, "allowed", "my own tool")
        self.store.set_status(resolved.key, "resolved")
        self.store.set_status(event.key, "resolved")
        self.scan([allowed, resolved, event], collectors=("processes", "eventlogs"))
        self.assertEqual(self.status(allowed), "allowed", "something marked expected stays suppressed")
        self.assertEqual(self.status(resolved), "open", "a dealt-with condition that is back must come back")
        self.assertEqual(self.status(event), "resolved", "re-reading the same old log entry must not reopen it")
        self.assertEqual(self.store.get_finding(allowed.key)["note"], "my own tool")

    def test_events_persist_then_age_out_by_when_they_were_learned(self):
        old = finding("old-event", kind="event", collector="eventlogs", when=time.time() - 200 * 86400)
        self.scan([old], collectors=("eventlogs",))
        self.scan([], collectors=("eventlogs", "processes"))
        self.assertEqual(self.status(old), "open", "an event from last quarter found today stays visible")
        with self.store._lock, self.store._db:
            self.store._db.execute("UPDATE findings SET first_seen=? WHERE id=?", (time.time() - (EVENT_TTL_DAYS + 1) * 86400, old.key))
        self.scan([], collectors=("processes",))
        self.assertEqual(self.status(old), "gone")

    def test_lookup_by_prefix_and_sorting(self):
        fs = [finding("x", "low"), finding("y", "critical"), finding("z", "medium", category="posture")]
        self.scan(fs)
        self.assertEqual(self.store.get_finding(fs[1].key[:6])["title"], "Finding y")
        self.assertIsNone(self.store.get_finding("zz"))
        self.assertEqual([r["severity"] for r in self.store.findings()], ["critical", "medium", "low"])
        self.assertEqual([r["severity"] for r in self.store.findings(min_severity="medium")], ["critical", "medium"])
        with self.assertRaises(ValueError):
            self.store.set_status(fs[0].key, "deleted")

    def test_baseline_marks_what_is_new(self):
        self.assertEqual(sorted(self.store.inventory_sync("autorun", {"a": {"name": "A"}, "b": {"name": "B"}})), ["a", "b"])
        self.assertIsNone(self.store.baseline_time())
        self.assertEqual(scan._baseline_findings(self.store), [], "nothing is 'new' before a baseline exists")
        self.assertEqual(self.store.baseline_accept(), 2)
        self.assertEqual(self.store.inventory_sync("autorun", {"a": {"name": "A"}, "c": {"name": "C", "kind": "run_key", "location": "HKCU\\Run"}}), ["c"])
        new = scan._baseline_findings(self.store)
        self.assertEqual([(f.rule, f.severity, f.entity["name"]) for f in new], [("baseline.new.autorun", "medium", "C")])
        self.store.inventory_sync("admin", {"S-1-5-21-9": {"name": "PC\\intruder"}})
        self.assertEqual(sorted(f.severity for f in scan._baseline_findings(self.store)), ["high", "medium"])

    def test_action_log(self):
        aid = self.store.log_action("policy", "suspend", {"pid": 5}, "f1", state="pending", reason="why")
        self.assertEqual(self.store.pending_for("f1", "suspend")["id"], aid)
        self.assertIsNone(self.store.pending_for("f1", "kill"))
        self.store.update_action(aid, state="approved", ok=True, result={"message": "done"})
        row = self.store.get_action(aid)
        self.assertEqual((row["state"], row["ok"], row["result"]["message"], row["target"]), ("approved", 1, "done", {"pid": 5}))
        with self.assertRaises(ValueError):
            self.store.update_action(aid, target_path="x")
        self.assertEqual(self.store.actions(state="pending"), [])

    def test_signature_cache_is_keyed_by_size_and_time(self):
        self.store.sig_put(r"C:\X\a.exe", 10, 1000.0, VENDOR)
        self.assertEqual(self.store.sig_get(r"c:\x\A.EXE", 10, 1000.0)["status"], "Valid")
        self.assertIsNone(self.store.sig_get(r"C:\X\a.exe", 11, 1000.0), "a changed file must be checked again")
        self.assertIsNone(self.store.sig_get(r"C:\X\a.exe", 10, 2000.0))

    def test_misc(self):
        self.assertTrue(self.store.net_observe(r"C:\a.exe", "198.51.100.1", 443))
        self.assertFalse(self.store.net_observe(r"c:\A.exe", "198.51.100.1", 443))
        self.store.kv_set("k", "v")
        self.assertEqual((self.store.kv_get("k"), self.store.kv_get("missing", "d")), ("v", "d"))
        run = self.store.start_run("monitor", False)
        self.store.end_run(run, {}, {})
        self.assertIsNone(self.store.last_run(), "the monitor's bookkeeping is not a scan")


class Helpers(unittest.TestCase):
    @unittest.skipUnless(WINDOWS, "Windows PowerShell")
    def test_helpers_work_when_started_from_a_powershell_7_terminal(self):
        """PowerShell 7 exports a module path that breaks Windows PowerShell's own modules. HostGuard must not pass it on."""
        from hostguard import sigs
        broken = os.path.join(_TMP, "ps7-modules", "Microsoft.PowerShell.Security")
        os.makedirs(broken, exist_ok=True)
        Path(broken, "Microsoft.PowerShell.Security.psd1").write_text(     # newer than the built-in one, and unloadable here
            "@{ ModuleVersion = '7.0.0.0'; GUID = 'a94c8c7e-9810-47c0-b8af-65089c13a35a'; PowerShellVersion = '99.0'; "
            "CmdletsToExport = @('Get-AuthenticodeSignature') }", encoding="utf-8")
        notepad = os.path.join(paths.SYSTEM32, "notepad.exe")
        before = os.environ.get("PSModulePath")
        os.environ["PSModulePath"] = os.path.dirname(broken) + os.pathsep + (before or "")
        try:
            probe = [paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", "(Get-AuthenticodeSignature -LiteralPath $env:ComSpec).Status"]
            raw = subprocess.run(probe, capture_output=True, text=True, creationflags=util.NO_WINDOW, stdin=subprocess.DEVNULL)
            self.assertIn("could not be loaded", raw.stderr, "the stand-in module must break an unprotected PowerShell, or this test proves nothing")
            self.assertNotIn("PSMODULEPATH", {k.upper() for k in util.child_env()})
            sig = sigs.check(None, [notepad], use_cache=False)[notepad.lower()]
            self.assertEqual(sig["status"], "Valid", "signature checks must survive a foreign module path")
        finally:
            if before is None:
                os.environ.pop("PSModulePath", None)
            else:
                os.environ["PSModulePath"] = before

    @unittest.skipUnless(WINDOWS, "short names, junctions and app sandboxes are Windows things")
    def test_only_an_app_sandbox_counts_as_a_private_copy(self):
        import ctypes
        import subprocess
        folder = os.path.join(_TMP, "A folder with a long name")
        os.makedirs(folder, exist_ok=True)
        target = os.path.join(folder, "file.bin")
        Path(target).write_bytes(b"x")
        self.assertFalse(util.is_redirected(target))
        self.assertFalse(util.is_redirected(os.path.join(folder, "missing.bin")))
        buf = ctypes.create_unicode_buffer(600)
        if ctypes.windll.kernel32.GetShortPathNameW(target, buf, 600) and buf.value.lower() != target.lower():
            self.assertTrue(os.path.isfile(buf.value))
            self.assertFalse(util.is_redirected(buf.value), "a short 8.3 name is the same file, not a private copy")
        link = os.path.join(_TMP, "junction")
        made = subprocess.run(["cmd", "/c", "mklink", "/J", link, folder], capture_output=True,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if made.returncode == 0:
            self.assertFalse(util.is_redirected(os.path.join(link, "file.bin")), "a junction is not a private copy")
            os.rmdir(link)

    def test_split_command(self):
        cases = {
            r'"C:\Program Files\App\app.exe" --flag x': (r"C:\Program Files\App\app.exe", "--flag x"),
            r"C:\Program Files\NZXT CAM\NZXT CAM.exe --startup": (r"C:\Program Files\NZXT CAM\NZXT CAM.exe", "--startup"),
            r"rundll32.exe shell32.dll,Control_RunDLL": ("rundll32.exe", "shell32.dll,Control_RunDLL"),
            '"\\"C:\\Users\\a\\app\\x.exe\\" --startup"': (r"C:\Users\a\app\x.exe", "--startup"),
            "": ("", ""),
        }
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(util.split_command(cmd), want)

    def test_path_zones(self):
        zones = {r"C:\Windows\System32\cmd.exe": "windows", r"C:\Windows\Temp\x.exe": "temp", r"C:\Program Files\A\a.exe": "program_files",
                 r"C:\Users\a\AppData\Local\Temp\x.exe": "temp", r"C:\Users\a\Downloads\x.exe": "downloads",
                 r"C:\Users\a\AppData\Roaming\x\y.exe": "appdata", r"C:\Users\Public\x.exe": "public", r"C:\ProgramData\x\y.exe": "programdata",
                 r"C:\$Recycle.Bin\S-1\x.exe": "recycle", r"C:\x.exe": "root", r"D:\Games\g.exe": "other", r"\\server\share\x.exe": "network",
                 r"C:\Users\a\OneDrive\Desktop\x.exe": "desktop"}
        for path, zone in zones.items():
            with self.subTest(path=path):
                self.assertEqual(util.path_zone(path), zone)
        self.assertNotIn("windows", util.USER_WRITABLE)
        self.assertNotIn("program_files", util.USER_WRITABLE)
        self.assertTrue(util.is_under(r"C:\Lab\Tools\x.exe", [r"c:\lab"]))
        self.assertFalse(util.is_under(r"C:\Laboratory\x.exe", [r"C:\Lab"]))

    def test_addresses_and_times(self):
        self.assertTrue(util.is_public_ip("8.8.8.8"))
        for ip in ("192.168.1.1", "10.0.0.1", "127.0.0.1", "100.64.10.20", "169.254.1.1", "::1", "fe80::1%12", "not-an-ip", ""):
            self.assertFalse(util.is_public_ip(ip), ip)
        self.assertTrue(util.is_mesh_vpn_ip("100.64.10.20"))
        self.assertFalse(util.is_mesh_vpn_ip("100.128.0.1"))
        self.assertAlmostEqual(util.parse_time("2026-11-01T10:00:00.1234567Z"), 1793527200.123456, places=3)
        self.assertAlmostEqual(util.parse_time("/Date(1793527200000)/"), 1793527200.0)
        self.assertIsNone(util.parse_time("garbage"))
        self.assertEqual((util.levenshtein("svchost.exe", "svch0st.exe", 1), util.levenshtein("abc", "abcdefgh", 1)), (1, 2))
        self.assertGreater(util.entropy(os.urandom(4096)), 7.5)
        self.assertLess(util.entropy(b"aaaa" * 1000), 0.1)

    def test_settings_are_validated(self):
        self.addCleanup(lambda: paths.save_config(paths.DEFAULTS))
        self.assertEqual(paths.set_value("containment.mode", "auto")["containment"]["mode"], "auto")
        self.assertTrue(paths.set_value("containment.isolate_on_critical", "on")["containment"]["isolate_on_critical"])
        self.assertEqual(paths.set_value("trusted.paths", r"C:\Lab; D:\Samples")["trusted"]["paths"], [r"C:\Lab", r"D:\Samples"])
        for key, value in (("containment.mode", "yolo"), ("containment.nope", "x"), ("nope.mode", "x"), ("containment.max_auto_actions_per_hour", "-3"),
                           ("containment.isolate_on_critical", "maybe"), ("containment", "x")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                paths.set_value(key, value)
        paths.config_path().write_text("{ this is not json", encoding="utf-8")
        self.assertEqual(paths.load_config()["containment"]["mode"], "ask", "a broken settings file falls back to safe defaults")

    def test_shortcut_parser(self):
        target = r"C:\Windows\System32\cmd.exe".encode("latin-1") + b"\x00"
        info_body = b"\x00" * 0x11 + target + b"\x00"
        header_size = 0x1C
        info = struct.pack("<7I", header_size + len(info_body), header_size, 1, header_size, header_size + 0x11, 0,
                           header_size + 0x11 + len(target)) + info_body
        args = "/c echo hi".encode("utf-16-le")
        data = struct.pack("<I16sI", 0x4C, b"\x01" * 16, 0x2 | 0x20 | 0x80) + b"\x00" * (0x4C - 24) + info + struct.pack("<H", len(args) // 2) + args
        parsed = lnk.parse_bytes(data)
        self.assertEqual((parsed["target"], parsed["args"]), (r"C:\Windows\System32\cmd.exe", "/c echo hi"))
        self.assertIsNone(lnk.parse_bytes(b"not a shortcut"))
        self.assertIsNotNone(lnk.parse_bytes(data[:0x60]), "a truncated shortcut must not raise")

    def test_trusted_folders_mark_down_but_keep_findings(self):
        fs = [finding("lab", "critical", entity={"type": "file", "path": r"C:\Lab\samples\x.exe"}),
              finding("real", "critical", entity={"type": "file", "path": r"C:\Users\a\Downloads\x.exe"})]
        scan.apply_trusted_paths(fs, [r"C:\Lab"])
        self.assertEqual([(f.severity, f.tags) for f in fs], [("low", ["trusted-path"]), ("critical", [])])

    def test_reports_render(self):
        store = fresh_store()
        self.addCleanup(store.close)
        run = store.start_run("quick", False)
        store.upsert_findings(run, [finding("a", "critical", description="Bad thing.", evidence={"path": r"C:\x.exe", "list": ["1", "2"]}).to_row(),
                                    finding("p", "medium", category="posture").to_row()], ["processes"])
        store.end_run(run, {"ran": ["processes"]}, {"seconds": 1.5, "coverage": {"notes": ["could not see X"], "gaps": []}})
        text = report.text(store, detail=True)
        for needle in ("Signs of compromise", "Finding a", "HARDENING", "could not see X", "Baseline: not set"):
            self.assertIn(needle, text)
        md = report.markdown(store)
        self.assertIn("### [critical] Finding a", md)
        self.assertIn("| critical | 1 | 0 |", md)


class AddOns(unittest.TestCase):
    def test_yara_output_parsing(self):
        out = "Win_Trojan_Generic C:\\Users\\a\\Downloads\\a b\\bad file.exe\r\nSecond_Rule C:\\Users\\a\\Downloads\\a b\\bad file.exe\r\nerror scanning x\r\n\r\n"
        m = components.parse_yara(out)
        self.assertEqual(m, [{"rule": "Win_Trojan_Generic", "path": r"C:\Users\a\Downloads\a b\bad file.exe"},
                             {"rule": "Second_Rule", "path": r"C:\Users\a\Downloads\a b\bad file.exe"}])
        fs = components.yara_findings(m + [{"rule": "Loose_Rule", "path": r"C:\Program Files\A\ok.exe"}],
                                      {r"c:\program files\a\ok.exe": VENDOR, r"c:\users\a\downloads\a b\bad file.exe": UNSIGNED})
        sev = {f.entity["path"]: f.severity for f in fs}
        self.assertEqual(sev, {r"C:\Users\a\Downloads\a b\bad file.exe": "high", r"C:\Program Files\A\ok.exe": "low"})

    def test_hollows_hunter_report(self):
        text = "HollowsHunter v.0.4.1.1 (x64)\nBuilt on: Sep 13 2025\n" + json.dumps({
            "scan_date_time": "x", "scanned_count": 200, "failed_count": 50, "suspicious_count": 2,
            "suspicious": [{"pid": 10, "name": "x.exe", "replaced": 1, "implanted_pe": 0}, {"pid": 11, "name": "game.exe", "implanted_shc": 2}]})
        rep = components.parse_hollows(text)
        self.assertEqual(rep["suspicious_count"], 2)
        procs = [{"pid": 10, "name": "x.exe", "path": r"C:\Users\a\AppData\Local\Temp\x.exe"}, {"pid": 11, "name": "game.exe", "path": r"C:\Games\game.exe"}]
        fs = components.hollows_findings(rep, procs, {r"c:\users\a\appdata\local\temp\x.exe": UNSIGNED, r"c:\games\game.exe": VENDOR})
        self.assertEqual({f.entity["pid"]: f.severity for f in fs}, {10: "high", 11: "low"})
        self.assertIsNone(components.parse_hollows("banner only, no report"))
        self.assertEqual(components.hollows_findings(None, procs, {}), [])

    def test_hayabusa_records(self):
        lines = [json.dumps({"Timestamp": "2026-11-10 08:06:57.658 -07:00", "RuleTitle": "Proc Injection", "Level": "high", "Channel": "Sysmon",
                             "EventID": 8, "RecordID": 5, "Details": {"Src": "a.exe"}, "RuleID": "abc"}),
                 json.dumps({"Timestamp": "2026-11-11 09:00:00.000 -07:00", "RuleTitle": "Proc Injection", "Level": "high", "Channel": "Sysmon",
                             "EventID": 8, "RecordID": 9, "Details": {"Src": "b.exe"}}),
                 json.dumps({"Timestamp": "2026-11-11 09:00:00.000 -07:00", "RuleTitle": "Logon", "Level": "info", "Channel": "Sec", "EventID": 4624}),
                 "not json", json.dumps({"no": "title"})]
        recs = components.parse_hayabusa("\n".join(lines))
        self.assertEqual(len(recs), 3)
        fs = components.hayabusa_findings(recs)
        self.assertEqual([(f.title, f.severity, f.evidence["times"]) for f in fs], [("Sigma rule fired: Proc Injection", "high", 2),
                                                                                    ("Sigma rule fired: Logon", "info", 1)])
        self.assertIn("b.exe", fs[0].evidence["details"])
        self.assertEqual(fs[0].kind, "event")

    def test_status_lists_every_add_on_as_missing_by_default(self):
        rows = {r["id"]: r for r in components.status()}
        self.assertEqual(sorted(rows), ["hayabusa", "hollows_hunter", "sysmon", "yara"])
        for name in ("yara", "hollows_hunter", "hayabusa"):
            self.assertFalse(rows[name]["installed"])
            self.assertIn("github.com", rows[name]["get"])
            self.assertIn(os.path.join(_TMP, "state", "tools"), rows[name]["place"])

    @unittest.skipUnless(WINDOWS, "the stand-in tools are batch files")
    def test_stand_in_executables_are_driven_correctly(self):
        work = os.path.join(_TMP, "stubs")
        os.makedirs(os.path.join(work, "rules"), exist_ok=True)
        Path(work, "rules", "core.yar").write_text("rule x { condition: false }")
        target = os.path.join(work, "scan me")
        os.makedirs(target, exist_ok=True)
        Path(work, "yara-out.txt").write_text(f"Stub_Rule {target}\\bad.exe\n")
        Path(work, "yara64.cmd").write_text('@echo off\r\necho %* > "%~dp0yara-args.txt"\r\ntype "%~dp0yara-out.txt"\r\n')
        Path(work, "hh-out.txt").write_text('HollowsHunter banner\n{"scanned_count": 3, "failed_count": 1, "suspicious_count": 1, "suspicious": [{"pid": 42, "name": "x.exe", "implanted_pe": 1}]}\n')
        Path(work, "hollows_hunter64.cmd").write_text('@echo off\r\necho %* > "%~dp0hh-args.txt"\r\ntype "%~dp0hh-out.txt"\r\nexit /b 2\r\n')
        os.environ.update(HOSTGUARD_YARA=os.path.join(work, "yara64.cmd"), HOSTGUARD_YARA_RULES=os.path.join(work, "rules"),
                          HOSTGUARD_HOLLOWS_HUNTER=os.path.join(work, "hollows_hunter64.cmd"))
        try:
            matches = components.yara_scan([target, os.path.join(work, "does-not-exist")])
            self.assertEqual(matches, [{"rule": "Stub_Rule", "path": target + "\\bad.exe"}])
            args = Path(work, "yara-args.txt").read_text()
            for flag in ("-w", "-r", "-a 180", "core.yar"):
                self.assertIn(flag, args)
            self.assertTrue(args.strip().endswith('"' + target + '"') or args.strip().endswith(target), args)
            rep = components.hollows_scan()
            self.assertEqual(rep["suspicious"][0]["pid"], 42)
            self.assertEqual(Path(work, "hh-args.txt").read_text().split(), ["-json", "-quiet", "-ofilter", "2"])
            self.assertTrue({r["id"]: r["installed"] for r in components.status()}["yara"])
        finally:
            for k in ("HOSTGUARD_YARA", "HOSTGUARD_YARA_RULES", "HOSTGUARD_HOLLOWS_HUNTER"):
                os.environ.pop(k, None)


@unittest.skipUnless(WINDOWS, "the dashboard reads Windows state")
class DashboardApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hostguard import api
        cls.api_mod = api
        cfg = json.loads(json.dumps(paths.DEFAULTS))
        cfg["agent"]["endpoint"] = "http://127.0.0.1:9/v1"       # nothing listens there: the tests never touch a real model
        paths.save_config(cfg)
        cls.api = api.Api()
        cls.work = os.path.join(_TMP, "api-work")
        os.makedirs(cls.work, exist_ok=True)

    def wait(self, task_id, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            t = next(t for t in self.api.tasks.snapshot() if t["id"] == task_id)
            if t["state"] != "running":
                return t
            time.sleep(0.1)
        self.fail("the task did not finish")

    def add(self, f: Finding) -> str:
        s = Store()
        try:
            s.upsert_findings(s.start_run("test", False), [f.to_row()])
        finally:
            s.close()
        return f.key

    def test_status_has_what_the_page_needs(self):
        st = self.api.get("status", {})
        for key in ("verdict", "findings", "pending", "actions", "quarantine", "monitor", "isolation", "containment", "agent",
                    "defender", "tasks", "trusted_paths", "state_folder", "sandboxed_python", "addons", "notify", "canaries"):
            self.assertIn(key, st)
        self.assertEqual((st["canaries"]["on"], st["canaries"]["alarm"], st["canaries"]["record"]), (False, None, "none"))
        self.assertIsInstance(st["canaries"]["plan"], list)
        self.assertIn("canary_checked", st["monitor"])
        self.assertIn(st["isolation"]["isolated"], (True, False, None))
        self.assertNotIn("api_key", st["agent_cfg"])
        json.dumps(st)   # everything must be serialisable
        self.assertEqual(len(self.api.get("hardening", {})["settings"]), 13)

    def test_unknown_and_malformed_requests_are_refused(self):
        ApiError = self.api_mod.ApiError
        for call in (lambda: self.api.get("nope", {}), lambda: self.api.post("nope", {}), lambda: self.api.get("finding", {"id": "zzzz"}),
                     lambda: self.api.post("scan", {"profile": "everything"}), lambda: self.api.post("monitor", {"on": "yes"}),
                     lambda: self.api.post("setting", {"key": "agent.api_key", "value": "x"}),
                     lambda: self.api.post("setting", {"key": "containment.mode", "value": "yolo"}),
                     lambda: self.api.post("setting", {"key": "agent.endpoint", "value": "file:///etc/passwd"}),
                     lambda: self.api.post("contain", {"id": "zzzz", "action": "suspend"}),
                     lambda: self.api.post("contain", {"id": "zzzz", "action": "format_disk"}),
                     lambda: self.api.post("approve", {"action_id": "x"}), lambda: self.api.post("isolate", {"on": 1}),
                     lambda: self.api.post("harden", {"setting": "nope", "on": True}), lambda: self.api.post("ask", {"question": "?"}),
                     lambda: self.api.post("quarantine", {"what": "restore", "id": "../../x"}),
                     lambda: self.api.post("finding/status", {"id": "zzzz", "status": "allow"}),
                     lambda: self.api.post("defender", {"what": "uninstall"}), lambda: self.api.post("canary", {"on": "yes"})):
            with self.assertRaises(ApiError):
                call()
        self.assertTrue(issubclass(ApiError, ValueError))

    def test_settings_and_dispositions(self):
        self.assertTrue(self.api.post("setting", {"key": "containment.mode", "value": "off"})["ok"])
        self.assertEqual(self.api.get("status", {})["containment"]["mode"], "off")
        self.api.post("setting", {"key": "containment.mode", "value": "ask"})
        self.api.post("setting", {"key": "trusted.paths", "value": [r"C:\Lab"]})
        self.assertEqual(self.api.get("status", {})["trusted_paths"], [r"C:\Lab"])
        self.api.post("setting", {"key": "trusted.paths", "value": []})
        fid = self.add(finding("api-allow", "medium"))
        self.assertIn(fid, [f["id"] for f in self.api.get("status", {})["findings"]])
        self.api.post("finding/status", {"id": fid, "status": "allow", "note": "mine"})
        self.assertNotIn(fid, [f["id"] for f in self.api.get("status", {})["findings"]])
        self.assertEqual(self.api.get("finding", {"id": fid})["note"], "mine")

    def test_contain_undo_and_approval_through_the_dashboard(self):
        target = os.path.join(self.work, "dropper.exe")
        Path(target).write_bytes(b"MZ" + b"\x00" * 100)
        fid = self.add(finding("api-file", "high", category="file", collector="files", entity={"type": "file", "path": target}, actions=["quarantine"]))
        task = self.wait(self.api.post("contain", {"id": fid, "action": "quarantine"})["task"])
        self.assertEqual(task["state"], "done", task["log"])
        self.assertFalse(os.path.exists(target))
        st = self.api.get("status", {})
        self.assertEqual(len([q for q in st["quarantine"] if q["original"] == target]), 1)
        self.assertEqual(next(f for f in st["findings"] if f["id"] == fid)["status"], "contained")
        done = next(a for a in st["actions"] if a["action"] == "quarantine" and a["target"] == target)
        self.assertTrue(done["undoable"])
        self.assertEqual(self.wait(self.api.post("undo", {"action_id": done["id"]})["task"])["state"], "done")
        self.assertTrue(os.path.exists(target))
        # a request waiting for approval, denied
        s = Store()
        try:
            from hostguard import contain
            aid = contain.propose(s, "quarantine", {"type": "file", "path": target}, fid, "test request")
        finally:
            s.close()
        self.assertIn(aid, [p["id"] for p in self.api.get("status", {})["pending"]])
        self.assertEqual(self.wait(self.api.post("approve", {"action_id": aid, "approve": False})["task"])["state"], "done")
        self.assertTrue(os.path.exists(target))
        self.assertNotIn(aid, [p["id"] for p in self.api.get("status", {})["pending"]])

    def test_a_hardening_entry_can_be_undone_from_the_action_log(self):
        """The administrator helper and Windows' answer are stand-ins here: no setting on this PC is touched."""
        from unittest import mock
        from hostguard import harden

        def logged(setting):
            s = Store()
            try:
                return s.log_action("operator", "harden:" + setting, {"type": "setting", "name": setting, "on": True}, None, state="done",
                                    ok=True, result={"message": "x"}, rollback={"kind": "harden", "setting": setting, "on": False})
            finally:
                s.close()
        entry, one_way = logged("pua_block"), logged("sysmon")          # the second as older versions recorded it
        rows = {a["id"]: a for a in self.api.get("status", {})["actions"]}
        self.assertEqual((rows[entry]["undoable"], rows[one_way]["undoable"]), (True, False))
        asked = []

        def helper(verb, args=None, timeout=300, dry_run=False):
            asked.append((verb, dict(args or {})))
            return {"ok": True, "declined": False, "message": "set", "changes": []}
        with mock.patch.object(harden.elevate, "run", helper), mock.patch.object(harden, "_states", lambda: {"pua_block": False}):
            task = self.wait(self.api.post("undo", {"action_id": entry})["task"])
        self.assertEqual((task["state"], asked), ("done", [("harden", {"setting": "pua_block", "on": False})]), task["log"])
        self.assertIn("administrator rights", task["log"][0])
        self.assertEqual(task["log"][-1], "Done: Block potentially unwanted apps: now off")
        rows = {a["id"]: a for a in self.api.get("status", {})["actions"]}
        self.assertEqual((rows[entry]["undone"] is not None, rows[entry]["undoable"]), (True, False))

    def test_only_one_scan_at_a_time_but_actions_are_never_queued_behind_it(self):
        import threading
        gate = threading.Event()
        first = self.api.tasks.start("Quick scan", lambda log: gate.wait(20), kind="scan", exclusive=True)
        try:
            with self.assertRaises(self.api_mod.ApiError):
                self.api.post("scan", {"profile": "quick"})
            other = self.api.tasks.start("Suspend", lambda log: {"ok": True, "message": "fine"}, kind="action")
            self.assertEqual(self.wait(other["task"])["state"], "done")
            self.assertTrue(self.api.get("status", {})["scanning"])
        finally:
            gate.set()
        self.assertEqual(self.wait(first["task"])["state"], "done")

    def test_a_failing_task_is_reported_not_raised(self):
        def boom(log):
            raise RuntimeError("kaboom")
        t = self.wait(self.api.tasks.start("Broken", boom)["task"])
        self.assertEqual(t["state"], "failed")
        self.assertIn("kaboom", t["log"][-1])
        t = self.wait(self.api.tasks.start("Refused", lambda log: {"ok": False, "message": "refused: no"})["task"])
        self.assertEqual((t["state"], t["log"][-1]), ("failed", "Failed: refused: no"))


if __name__ == "__main__":
    unittest.main()
