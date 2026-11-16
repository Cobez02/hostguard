"""Change tracking: how much a new autorun matters depends on what it starts.

A signed program that updates itself re-registers dozens of startup entries in one go (OneDrive
does, with about thirty). That is worth listing. It must not read like an intrusion, and it must
not open a door for an entry that merely hides behind a signed shell.
"""

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix="hg-test-baseline-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import scan  # noqa: E402
from hostguard.store import Store  # noqa: E402

VENDOR = {"status": "Valid", "signer": "CN=Example Software Ltd", "issuer": "", "is_os": False}
UNSIGNED = {"status": "NotSigned", "signer": "", "issuer": "", "is_os": False}
MISSING = {"status": "Missing", "signer": "", "issuer": "", "is_os": False}

APP = r"C:\Users\a\AppData\Local\Vendor\App\26.1"
SIGNED = APP + r"\Sync.exe"
DROPPED = r"C:\Users\a\AppData\Roaming\upd\helper.exe"
GONE = r"C:\Users\a\gone.exe"
CMD = r"C:\WINDOWS\system32\cmd.exe"
SIGS = {SIGNED.lower(): VENDOR, DROPPED.lower(): UNSIGNED, GONE.lower(): MISSING, CMD.lower(): VENDOR,
        r"c:\windows\system32\rundll32.exe": VENDOR}


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


def grade(image, command=""):
    return scan._new_autorun_severity({"image": image, "command": command or image}, SIGS)[0]


class NewAutoruns(unittest.TestCase):
    def test_a_validly_signed_program_is_low(self):
        self.assertEqual(grade(SIGNED), "low")
        self.assertIn("signed by", scan._new_autorun_severity({"image": SIGNED, "command": SIGNED}, SIGS)[1])

    def test_unsigned_or_unchecked_stays_medium(self):
        self.assertEqual(grade(DROPPED), "medium")
        self.assertEqual(grade(GONE), "medium", "a program that could not be checked is not waved through")
        self.assertEqual(grade(r"C:\Users\a\never-checked.exe"), "medium")
        self.assertEqual(grade(""), "medium")

    def test_a_command_that_can_only_delete_is_low(self):
        self.assertEqual(grade(CMD, CMD + r' /q /c del /q "C:\Users\a\AppData\Local\Vendor\App\Update\Setup.exe"'), "low")
        self.assertEqual(grade(CMD, CMD + r' /q /c rmdir /s /q "C:\Users\a\AppData\Local\Vendor\App\25.9"'), "low")

    def test_a_signed_shell_proves_nothing_about_its_command(self):
        for tail in (r' /q /c del /q "C:\x" & calc.exe', r" /c powershell -enc AAAA", r' /q /c del /q "C:\x" | more',
                     r" /q /c del /q %TEMP%\x", r' /q /c del /q "C:\x" > C:\y', r" /q /c start C:\Users\a\x.exe"):
            self.assertEqual(grade(CMD, CMD + tail), "medium", tail)
        self.assertEqual(grade(r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\Users\a\x.dll,Start"), "medium")

    def test_findings_carry_the_grade_and_the_reason(self):
        store = Store(os.path.join(_TMP, f"db-{time.time_ns()}.db"))
        try:
            store.inventory_sync("autorun", {"old": {"name": "Old", "kind": "run_key", "location": r"HKCU\Run", "image": SIGNED, "command": SIGNED}})
            store.baseline_accept()
            store.inventory_sync("autorun", {
                "update": {"name": "{021E4F06}", "kind": "com_hijack", "location": r"HKCU\Software\Classes\CLSID", "image": SIGNED, "command": SIGNED},
                "dropper": {"name": "Helper", "kind": "run_key", "location": r"HKCU\Run", "image": DROPPED, "command": DROPPED}})
            store.inventory_sync("admin", {"S-1-5-21-9": {"name": r"PC\intruder"}})
            got = {f.entity.get("name") or f.title: f for f in scan._baseline_findings(store, SIGS)}
            self.assertEqual(got["{021E4F06}"].severity, "low")
            self.assertIn("signed by", got["{021E4F06}"].evidence["assessment"])
            self.assertEqual(got["Helper"].severity, "medium")
            self.assertEqual(got["Helper"].actions, ["disable_autorun"])
            self.assertEqual([f.severity for f in got.values() if f.rule == "baseline.new.admin"], ["high"],
                             "a new administrator is never softened by any of this")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
