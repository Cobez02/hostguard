"""The baseline's bookkeeping, and the fixes that real use of the add-ons and the administrator scan forced.

  * A listener has one key whether or not its program's path can be read, so a scan that gains
    administrator data does not see every system port as new.
  * Accepting a baseline closes the findings whose only message was "this is new".
  * YARA is handed a list of files in the form it can read, not a folder of a million files.
  * The program the administrator helper may run unsigned is exactly the one the downloader pins.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-inventory-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import addons, components, paths, scan, util  # noqa: E402
from hostguard.collect import eventlogs  # noqa: E402
from hostguard.detect import network as d_network  # noqa: E402
from hostguard.model import Finding  # noqa: E402
from hostguard.store import Store  # noqa: E402


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    for k in ("HOSTGUARD_YARA", "HOSTGUARD_YARA_RULES"):
        os.environ.pop(k, None)
    shutil.rmtree(_TMP, ignore_errors=True)


def new_store() -> Store:
    return Store(os.path.join(_TMP, f"db-{time.time_ns()}.db"))


class ListenerKeys(unittest.TestCase):
    LISTEN = {"proto": "tcp", "state": "LISTEN", "laddr": "0.0.0.0", "lport": 135, "raddr": "", "rport": 0, "pid": 900}

    def keys(self, **process):
        return list(d_network.inventory({"processes": [{"pid": 900, **process}], "connections": [self.LISTEN]}))

    def test_one_key_whether_or_not_the_path_can_be_read(self):
        without = self.keys(name="svchost.exe", path="")
        with_path = self.keys(name="svchost.exe", path=r"C:\Windows\System32\svchost.exe")
        self.assertEqual(without, ["tcp|135|svchost.exe"])
        self.assertEqual(with_path, without, "administrator data must not make a known listener look new")

    def test_old_keys_are_merged_once_and_keep_what_was_accepted(self):
        path = os.path.join(_TMP, "merge.db")
        store = Store(path)
        store.inventory_sync("listener", {"tcp|135|svchost.exe": {"port": 135}, r"tcp|8930|c:\apps\py\pythonw.exe": {"port": 8930}})
        store.inventory_sync("autorun", {r"run_key|hkcu\run|x|c:\a\b.exe": {"name": "x"}})
        store.baseline_accept()
        store.inventory_sync("listener", {r"tcp|135|c:\windows\system32\svchost.exe": {"port": 135},
                                          r"tcp|445|c:\windows\system32\ntoskrnl.exe": {"port": 445}})
        store.kv_set("listener_keys", "1")              # as a version before the fix left it
        store.close()
        store = Store(path)
        try:
            self.assertEqual({r["key"]: r["baseline"] for r in store.inventory("listener")},
                             {"tcp|135|svchost.exe": 1, "tcp|8930|pythonw.exe": 1, "tcp|445|ntoskrnl.exe": 0})
            self.assertEqual([r["key"] for r in store.inventory(only_new=True)], ["tcp|445|ntoskrnl.exe"])
            self.assertEqual([r["key"] for r in store.inventory("autorun")], [r"run_key|hkcu\run|x|c:\a\b.exe"], "other kinds are untouched")
        finally:
            store.close()
        again = Store(path)
        try:
            self.assertEqual(len(again.inventory("listener")), 3, "the merge runs once")
        finally:
            again.close()


class AcceptingABaseline(unittest.TestCase):
    def test_it_closes_the_this_is_new_findings_and_nothing_else(self):
        store = new_store()
        try:
            rows = [Finding(rule="baseline.new.autorun", title="New autorun entry since the baseline: A", severity="low", category="persistence",
                            collector="baseline", key_parts=("autorun", "a")),
                    Finding(rule="monitor.new_autorun", title="New autorun entry: A", severity="low", category="persistence", kind="event",
                            collector="monitor", key_parts=("a",), when=time.time()),
                    Finding(rule="proc.impostor", title="Impostor", severity="high", category="process", collector="processes", key_parts=("p",))]
            store.upsert_findings(store.start_run("test", False), [f.to_row() for f in rows])
            store.inventory_sync("autorun", {"a": {"name": "A"}})
            self.assertEqual(scan.accept_baseline(store), 1)
            status = {r["rule"]: (r["status"], r.get("note")) for r in store.findings(None)}
            self.assertEqual(status["baseline.new.autorun"], ("resolved", "accepted into the baseline"))
            self.assertEqual(status["monitor.new_autorun"], ("resolved", "accepted into the baseline"))
            self.assertEqual(status["proc.impostor"][0], "open", "a real finding is not closed by accepting a baseline")
            self.assertIsNotNone(store.baseline_time())
        finally:
            store.close()


class EventLogMessages(unittest.TestCase):
    def test_a_registered_but_unstarted_log_says_what_to_do(self):
        real = util.run_cmd
        util.run_cmd = lambda argv, timeout=60, input_text=None: (4201, "", "The instance name passed was not recognized as valid by a WMI data provider.")
        try:
            with self.assertRaises(eventlogs.LogUnavailable) as caught:
                eventlogs.query("Microsoft-Windows-Sysmon/Operational", "*", 10)
        finally:
            util.run_cmd = real
        self.assertIn("Restart Windows once", str(caught.exception))


@unittest.skipUnless(WINDOWS, "the stand-in is a batch file")
class YaraFileList(unittest.TestCase):
    def test_the_list_is_written_the_way_yara_for_windows_reads_it(self):
        """YARA 4.6 reads its list file as UTF-16 with no byte-order mark. The stand-in checks exactly that."""
        work = Path(_TMP) / "yara-list"
        (work / "rules").mkdir(parents=True)
        (work / "rules" / "core.yar").write_text("rule x { condition: false }")
        stub = work / "stub.py"
        stub.write_text(
            "import sys\n"
            "args = sys.argv[1:]\n"
            "raw = open(args[-1], 'rb').read()\n"
            "assert not raw.startswith(bytes([0xFF, 0xFE])), 'a byte-order mark corrupts the first name'\n"
            "names = [n for n in raw.decode('utf-16-le').splitlines() if n]\n"
            "open(sys.argv[0] + '.args', 'w', encoding='utf-8').write(' '.join(args[:-1]))\n"
            "sys.stdout.buffer.write(''.join('Stub_Rule ' + n + chr(10) for n in names if 'bad' in n).encode('utf-8'))\n", encoding="utf-8")
        (work / "yara64.cmd").write_text(f'@echo off\r\n"{sys.executable}" -I "{stub}" %*\r\n')
        bad = work / "really bad.exe"
        plain = work / "fine.txt"
        accent = work / ("bad caf" + chr(233) + ".dll")
        big = work / "bad but huge.bin"
        for f in (bad, plain, accent):
            f.write_bytes(b"x")
        big.write_bytes(bytes(2 << 20))
        os.environ.update(HOSTGUARD_YARA=str(work / "yara64.cmd"), HOSTGUARD_YARA_RULES=str(work / "rules"))
        try:
            got = components.yara_scan_files([str(bad), str(plain), str(accent), str(big), str(work / "bad missing.exe"), str(bad)], max_mb=1)
            self.assertEqual(sorted(m["path"] for m in got), sorted([str(bad), str(accent)]), "missing and oversized files are left out")
            self.assertEqual({m["rule"] for m in got}, {"Stub_Rule"})
            args = Path(str(stub) + ".args").read_text(encoding="utf-8")
            self.assertIn("--scan-list", args)
            self.assertNotIn("-r ", args + " ", "a list scan never walks folders")
            self.assertEqual(components.yara_scan_files([]), [])
            self.assertEqual(components.yara_scan_files([str(work / "nothing here")]), [])
        finally:
            for k in ("HOSTGUARD_YARA", "HOSTGUARD_YARA_RULES"):
                os.environ.pop(k, None)


class ElevatedHelperAndPins(unittest.TestCase):
    def test_the_unsigned_program_it_may_run_is_the_one_that_is_pinned(self):
        script = (paths.PS_DIR / "elevated.ps1").read_text(encoding="utf-8").lower()
        program = addons.PINS["hayabusa"]["program"]
        self.assertRegex(program, r"^[0-9a-f]{64}$")
        self.assertIn(f"'{program}'", script, "elevated.ps1 and addons.PINS must name the same Hayabusa program")
        self.assertIn("$hayabusapinned", script)

    @unittest.skipUnless(WINDOWS, "needs Windows PowerShell")
    def test_every_powershell_helper_parses(self):
        """These scripts run with administrator rights or behind a UAC prompt, where a typo cannot be seen."""
        check = ("$bad = 0; foreach ($f in Get-ChildItem -LiteralPath $env:HG_PS_DIR -Filter *.ps1) { $errors = $null; "
                 "[void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errors); "
                 "if ($errors.Count) { $bad += $errors.Count; Write-Output ($f.Name + ': ' + $errors[0].Message) } }; exit $bad")
        r = subprocess.run([paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", check], capture_output=True, text=True,
                           env={**util.child_env(), "HG_PS_DIR": str(paths.PS_DIR)}, creationflags=util.NO_WINDOW, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, ""), r.stderr)


if __name__ == "__main__":
    unittest.main()
