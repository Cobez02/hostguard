"""The elevated helper, exercised in dry-run mode: every check runs, nothing changes, no UAC prompt.

What this proves: each verb parses its request, refuses what it must refuse, and announces the
exact changes it would make. What it cannot prove: that Windows accepts those changes when they
run for real with administrator rights."""

import json
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
_TMP = tempfile.mkdtemp(prefix="hg-test-elev-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import elevate, harden, paths, quarantine, winapi  # noqa: E402

SYS32 = paths.SYSTEM32


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


def dry(verb, **args):
    return elevate.run(verb, args, dry_run=True)


@unittest.skipUnless(WINDOWS, "needs Windows")
class ElevatedDryRun(unittest.TestCase):
    def assertRefused(self, res, fragment=""):
        self.assertFalse(res["ok"], res)
        self.assertIn("refused", res["message"])
        if fragment:
            self.assertIn(fragment, res["message"])
        self.assertEqual(res["changes"], [], "a refused request must not have planned anything")

    def test_unknown_verb(self):
        self.assertRefused(dry("format-disk"), "unknown verb")

    def test_process_verbs(self):
        pids = {name.lower(): pid for pid, _pp, name in winapi.list_pids()}
        self.assertRefused(dry("kill", pid=4), "kernel")
        self.assertRefused(dry("kill", pid=pids["csrss.exe"]), "core Windows process")
        self.assertRefused(dry("suspend", pid=pids["lsass.exe"]), "core Windows process")
        child = subprocess.Popen([os.path.join(SYS32, "cmd.exe"), "/q", "/k"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            time.sleep(0.3)
            created = winapi.process_created(child.pid)
            res = dry("kill", pid=child.pid, created=created)
            self.assertTrue(res["ok"] and res["dry_run"], res)
            self.assertEqual(len(res["changes"]), 1)
            self.assertIsNone(child.poll(), "a dry run must not stop the process")
            self.assertRefused(dry("kill", pid=child.pid, created=created - 900), "different program")
            self.assertTrue(dry("suspend", pid=child.pid, created=created)["ok"])
            self.assertFalse(winapi.is_suspended(child.pid))
        finally:
            child.kill()
            child.wait(timeout=5)
            child.stdin.close()

    def test_quarantine_destination_is_pinned_to_the_vault(self):
        src = os.path.join(_TMP, "evil.bin")
        Path(src).write_bytes(b"x")
        vault = str(quarantine.vault())
        good = os.path.join(vault, "incoming-1-2.bin")
        self.assertTrue(dry("quarantine", path=src, dest=good)["ok"])
        self.assertTrue(os.path.exists(src))
        self.assertRefused(dry("quarantine", path=src, dest=os.path.join(SYS32, "incoming-1-2.bin")), "vault")
        self.assertRefused(dry("quarantine", path=src, dest=os.path.join(vault, "..", "incoming-1-2.bin")), "vault")
        self.assertRefused(dry("quarantine", path=src, dest=os.path.join(vault, "evil.dll")), "vault")
        self.assertRefused(dry("quarantine", path=os.path.join(SYS32, "notepad.exe"), dest=good), "Windows folder")

    def test_services(self):
        self.assertRefused(dry("service-disable", service="WinDefend"), "Windows needs")
        self.assertRefused(dry("service-disable", service="EventLog"), "Windows needs")
        self.assertRefused(dry("service-disable", service="no such service 12345"), "no such service")
        self.assertRefused(dry("service-disable", service="a&b|c"), "not a service name")
        res = dry("service-disable", service="Spooler")
        self.assertTrue(res["ok"], res)
        self.assertIn("previous_start", res["data"])
        self.assertRefused(dry("service-restore", service="Spooler", start=9), "start type")

    def test_registry_is_limited_to_autorun_keys(self):
        run = r"Software\Microsoft\Windows\CurrentVersion\Run"
        self.assertTrue(dry("reg-value-delete", hive="HKLM", path=run, view=64, name="Something")["ok"])
        self.assertTrue(dry("reg-value-set", hive="HKLM", path=run, view=64, name="Something", value="x.exe", type="REG_SZ")["ok"])
        self.assertRefused(dry("reg-value-delete", hive="HKLM", path=r"SYSTEM\CurrentControlSet\Control\Lsa", view=64, name="x"), "not an autorun location")
        self.assertRefused(dry("reg-value-set", hive="HKLM", path=run + r"\..\..\Policies", view=64, name="x", value="y", type="REG_SZ"))
        self.assertRefused(dry("reg-value-delete", hive="HKCU", path=run, view=64, name="x"), "only HKLM")

    def test_firewall_verbs(self):
        self.assertRefused(dry("block-ip", ip="not an ip"), "not an IP")
        self.assertRefused(dry("block-ip", ip="127.0.0.1"), "this PC")
        res = dry("block-ip", ip="8.8.8.8")
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(res["changes"]), 2)
        self.assertTrue(all("HostGuard-Block-8.8.8.8" in c for c in res["changes"]))
        iso = dry("isolate")
        self.assertTrue(iso["ok"], iso)
        self.assertTrue(all("HostGuard-Isolation" in c for c in iso["changes"]))
        self.assertTrue(dry("release")["ok"])

    def test_tasks_and_accounts(self):
        self.assertRefused(dry("task-disable", task="not a path"), "not a task path")
        self.assertRefused(dry("task-disable", task=r"\Microsoft\Windows\Defrag\ScheduledDefrag"), "Windows' own")
        self.assertRefused(dry("task-disable", task=r"\HostGuardNoSuchTask"), "no such task")
        self.assertRefused(dry("user-disable", user=os.environ["USERNAME"], current=os.environ["USERNAME"]), "in use")
        self.assertRefused(dry("user-disable", user="no-such-user-xyz"), "no such local account")
        self.assertRefused(dry("wmi-remove", consumer="SCM Event Log Consumer", namespace="root/subscription"), "Windows' own")
        self.assertRefused(dry("wmi-remove", consumer="x", namespace="root/cimv2"), "namespace")

    def test_hardening_verbs(self):
        self.assertRefused(dry("harden", setting="make-me-a-sandwich", on=True), "unknown hardening")
        self.assertRefused(dry("harden", setting="sysmon", on=False), "no command")
        for setting, count in (("pua_block", 1), ("asr_standard", 3), ("asr_extended", 6), ("process_audit", 1),
                               ("script_block_logging", 1), ("rdp_off", 1), ("rdp_private_only", 1), ("one_click_isolation", 1),
                               ("network_protection", 1), ("controlled_folder_access", 1), ("cloud_block_high", 1)):
            for on in (True, False):
                res = dry("harden", setting=setting, on=on)
                self.assertTrue(res["ok"], (setting, on, res))
                self.assertEqual(len(res["changes"]), count, (setting, res["changes"]))

    def test_collect_only_writes_to_its_own_folder(self):
        self.assertRefused(dry("collect", outdir=SYS32, queries=[]), "output folder")
        self.assertTrue(dry("collect", outdir=str(paths.sub("elevated")), queries=[])["ok"])


@unittest.skipUnless(WINDOWS, "needs Windows")
class HardeningCatalog(unittest.TestCase):
    def test_every_switch_reports_a_state_read_from_windows(self):
        rows = harden.status()
        self.assertEqual({r["id"] for r in rows}, {c[0] for c in harden.CATALOG})
        for r in rows:
            self.assertIn(r["on"], (True, False, None), r)
            self.assertTrue(r["title"] and r["detail"])

    def test_set_state_dry_run_and_unknown(self):
        self.assertFalse(harden.set_state(None, "nope", True)["ok"])
        res = harden.set_state(None, "pua_block", True, dry_run=True)
        self.assertTrue(res["ok"] and res["dry_run"], res)

    def test_asr_ids_match_the_elevated_script(self):
        text = (paths.PS_DIR / "elevated.ps1").read_text(encoding="utf-8")
        for rule_id in harden.ASR_STANDARD + harden.ASR_EXTENDED:
            self.assertIn(rule_id, text)


class ElevatedCollection(unittest.TestCase):
    def test_latest_is_parsed_and_expires(self):
        d = paths.sub("elevated")
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
               '<EventID>4720</EventID><Level>0</Level><TimeCreated SystemTime="2026-11-01T10:00:00.0000000Z"/><EventRecordID>77</EventRecordID>'
               '<Channel>Security</Channel></System><EventData><Data Name="TargetUserName">backdoor</Data>'
               '<Data Name="SubjectUserName">Alice</Data></EventData></Event>')
        (d / "events-1.xml").write_text(xml, encoding="utf-8")
        latest = {"when": time.time(), "processes": [{"pid": 4321, "path": r"C:\x\svc.exe", "cmdline": "svc.exe -k", "user": "SYSTEM"}],
                  "defender": {"prefs": {"ExclusionPath": [r"C:\Users\Public"]}}, "secureboot": True,
                  "event_files": {"events-1.xml": "Security", "..\\..\\evil.xml": "Security"}}
        (d / "latest.json").write_text(json.dumps(latest), encoding="utf-8")
        got = elevate.load_latest()
        self.assertEqual(got["processes"][0]["pid"], 4321)
        self.assertEqual(got["events"]["Security"][0]["data"]["TargetUserName"], "backdoor")
        self.assertEqual(got["defender"]["prefs"]["ExclusionPath"], [r"C:\Users\Public"])
        self.assertTrue(got["secureboot"])
        latest["when"] = time.time() - 3 * 3600
        (d / "latest.json").write_text(json.dumps(latest), encoding="utf-8")
        self.assertIsNone(elevate.load_latest(), "an old collection must not be passed off as current")


if __name__ == "__main__":
    unittest.main()
