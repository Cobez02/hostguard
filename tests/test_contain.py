"""Containment, quarantine and policy, exercised for real on throwaway processes, files and registry
values that the test creates itself. Nothing outside the test's own temp folder and its own child
processes is touched. Needs Windows."""

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
_TMP = tempfile.mkdtemp(prefix="hg-test-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import contain, paths, policy, quarantine, reg, util, winapi  # noqa: E402
from hostguard.model import Finding  # noqa: E402
from hostguard.store import Store  # noqa: E402

WORK = os.path.join(_TMP, "work")
os.makedirs(WORK, exist_ok=True)
SYS32 = paths.SYSTEM32


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


def sleeper() -> subprocess.Popen:
    """A harmless child that stays alive: Windows' own command interpreter waiting on its input."""
    return subprocess.Popen([os.path.join(SYS32, "cmd.exe"), "/q", "/k"], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def reap(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    if proc.stdin:
        proc.stdin.close()


def entity_for(proc: subprocess.Popen) -> dict:
    return {"type": "process", "pid": proc.pid, "name": "cmd.exe", "created": winapi.process_created(proc.pid)}


def process_finding(proc: subprocess.Popen, severity="critical", confidence="high", tags=()) -> Finding:
    return Finding(rule="test.process", title="test process", severity=severity, confidence=confidence, category="process",
                   entity=entity_for(proc), actions=["suspend", "kill"], collector="test", key_parts=(proc.pid, time.time()),
                   tags=list(tags))


@unittest.skipUnless(WINDOWS, "needs Windows")
class Quarantine(unittest.TestCase):
    def test_round_trip_keeps_bytes_and_stores_them_inert(self):
        src = os.path.join(WORK, "sample.bin")
        body = b"MZ" + os.urandom(4096) + b"MARKER-STRING-1234567890"
        Path(src).write_bytes(body)
        res = quarantine.put(src, "f1", "unit test")
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(src))
        blob = (quarantine.vault() / f"{res['id']}.hgq").read_bytes()
        self.assertEqual(len(blob), len(body))
        self.assertNotIn(b"MARKER-STRING", blob)          # not recognisable, not runnable
        self.assertNotEqual(blob[:2], b"MZ")
        listed = [i for i in quarantine.items() if i["id"] == res["id"]]
        self.assertEqual(listed[0]["original"], src)
        self.assertNotIn("key", listed[0])
        back = quarantine.restore(res["id"])
        self.assertTrue(back["ok"], back)
        self.assertEqual(Path(src).read_bytes(), body)
        self.assertEqual(quarantine.items(), [i for i in quarantine.items() if i["id"] != res["id"]])

    def test_restore_into_appdata_lands_in_the_real_folder(self):
        """A Microsoft Store Python gets a private copy of any new file it creates under AppData.
        A restored file has to end up where the rest of Windows can see it."""
        target = os.path.join(os.environ["APPDATA"], f"hostguard-selftest-{time.time_ns()}.txt")
        seed = os.path.join(WORK, "seed.txt")
        Path(seed).write_text("payload")
        rc, _out, err = util.run_cmd([paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                                      str(paths.PS_DIR / "place.ps1"), "-Source", seed, "-Destination", target], timeout=120)
        self.assertEqual(rc, 0, err)
        self.addCleanup(lambda: os.path.exists(target) and os.remove(target))
        self.assertFalse(util.is_redirected(target))
        res = quarantine.put(target)
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(target))
        back = quarantine.restore(res["id"])
        self.assertTrue(back["ok"], back)
        self.assertFalse(back.get("relocated"), back)
        self.assertTrue(os.path.exists(target))
        self.assertFalse(util.is_redirected(target), "restored into a sandbox-private copy, invisible to other programs")
        self.assertEqual(Path(target).read_text(), "payload")

    def test_restore_falls_back_when_the_appdata_folder_is_gone(self):
        if not paths.python_is_sandboxed():
            self.skipTest("only a sandboxed Python needs the fallback")
        missing = os.path.join(os.environ["APPDATA"], f"hostguard-gone-{time.time_ns()}", "tool.txt")
        src = os.path.join(WORK, "relocate.txt")
        Path(src).write_text("x")
        res = quarantine.put(src)
        meta_path = quarantine.vault() / f"{res['id']}.json"
        meta = json.loads(meta_path.read_text())
        meta["original"] = missing                      # as if it had been quarantined from a folder that no longer exists
        meta_path.write_text(json.dumps(meta))
        back = quarantine.restore(res["id"])
        self.assertTrue(back["ok"] and back["relocated"], back)
        self.assertTrue(os.path.isfile(back["path"]))
        self.assertIn("restored", back["path"])
        self.assertFalse(os.path.exists(missing), "no private copy may be left behind pretending to be the real file")

    def test_restore_will_not_overwrite_without_asking(self):
        src = os.path.join(WORK, "again.txt")
        Path(src).write_text("first")
        res = quarantine.put(src)
        Path(src).write_text("second")
        self.assertFalse(quarantine.restore(res["id"])["ok"])
        self.assertEqual(Path(src).read_text(), "second")
        self.assertTrue(quarantine.restore(res["id"], overwrite=True)["ok"])
        self.assertEqual(Path(src).read_text(), "first")

    def test_ids_cannot_escape_the_vault(self):
        for bad in ("..\\..\\x", "../x", "20260101-000000-zzzzzz", ""):
            self.assertFalse(quarantine.restore(bad)["ok"])
            self.assertFalse(quarantine.delete(bad)["ok"])

    def test_delete_is_permanent(self):
        src = os.path.join(WORK, "gone.txt")
        Path(src).write_text("x")
        res = quarantine.put(src)
        self.assertTrue(quarantine.delete(res["id"])["ok"])
        self.assertFalse(quarantine.restore(res["id"])["ok"])


@unittest.skipUnless(WINDOWS, "needs Windows")
class FileGuardrails(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.close)

    def refused(self, action, entity, actor="operator", force=False):
        res = contain.execute(self.store, action, entity, actor=actor, force=force)
        self.assertFalse(res["ok"], res)
        self.assertTrue(res.get("refused"), res)
        return res["message"]

    def test_windows_files_are_never_quarantined(self):
        target = os.path.join(SYS32, "notepad.exe")
        self.assertIn("Windows folder", self.refused("quarantine", {"path": target}))
        self.assertIn("Windows folder", self.refused("quarantine", {"path": target}, force=True))
        self.assertTrue(os.path.isfile(target))

    def test_hostguard_does_not_quarantine_itself(self):
        self.assertIn("HostGuard", self.refused("quarantine", {"path": str(ROOT / "run.py")}, force=True))

    def test_missing_file(self):
        self.assertIn("not a file", self.refused("quarantine", {"path": os.path.join(WORK, "nope.exe")}))

    def test_microsoft_signed_copy_needs_force(self):
        copy = os.path.join(WORK, "notepad-copy.exe")
        shutil.copyfile(os.path.join(SYS32, "notepad.exe"), copy)
        self.assertIn("signed by Microsoft", self.refused("quarantine", {"path": copy}))
        res = contain.execute(self.store, "quarantine", {"path": copy}, force=True)
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(copy))
        self.assertTrue(contain.undo(self.store, res["action_id"])["ok"])
        self.assertTrue(os.path.exists(copy))

    def test_automatic_quarantine_only_takes_unsigned_files(self):
        signed = os.path.join(WORK, "python-copy.exe")
        shutil.copyfile(sys.executable if os.path.getsize(sys.executable) > 0 else os.path.join(sys.base_prefix, "python.exe"), signed)
        msg = self.refused("quarantine", {"path": signed}, actor="auto-policy")
        self.assertIn("only takes unsigned", msg)
        unsigned = os.path.join(WORK, "unsigned.exe")
        Path(unsigned).write_bytes(b"MZ" + b"\x00" * 200)
        res = contain.execute(self.store, "quarantine", {"path": unsigned}, actor="auto-policy")
        self.assertTrue(res["ok"], res)

    def test_automatic_quarantine_leaves_a_file_it_could_not_check(self):
        """Unknown is not guilty: no verdict on the signature means no automatic action."""
        target = os.path.join(WORK, "mystery.exe")
        Path(target).write_bytes(b"MZ" + b"\x00" * 200)
        real = contain._sig
        try:
            for unknown in (None, {"status": "Unreadable", "signer": "", "issuer": "", "is_os": False},
                            {"status": "Missing", "signer": "", "issuer": "", "is_os": False}):
                contain._sig = lambda path, _u=unknown: _u
                msg = self.refused("quarantine", {"path": target}, actor="auto-policy")
                self.assertIn("could not be checked", msg)
                self.assertTrue(os.path.isfile(target))
            contain._sig = lambda path: {"status": "HashMismatch", "signer": "CN=Someone", "issuer": "", "is_os": False}
            res = contain.execute(self.store, "quarantine", {"path": target}, actor="auto-policy")
            self.assertTrue(res["ok"], "a file altered after it was signed is fair game: " + str(res))
            Path(target).write_text("@echo off")
            contain._sig = real
            res = contain.execute(self.store, "quarantine", {"path": target}, actor="auto-policy")
            self.assertTrue(res["ok"], "a file that cannot carry a signature counts as unsigned: " + str(res))
        finally:
            contain._sig = real

    def test_trusted_folder_blocks_automatic_action_only(self):
        cfg = paths.load_config()
        cfg["trusted"]["paths"] = [WORK]
        paths.save_config(cfg)
        self.addCleanup(lambda: paths.save_config(paths.DEFAULTS))
        target = os.path.join(WORK, "lab-tool.exe")
        Path(target).write_bytes(b"MZ" + b"\x00" * 64)
        self.assertIn("trusted", self.refused("quarantine", {"path": target}, actor="auto-policy"))
        self.assertTrue(contain.execute(self.store, "quarantine", {"path": target}, actor="operator")["ok"])

    def test_dry_run_changes_nothing(self):
        target = os.path.join(WORK, "dry.exe")
        Path(target).write_bytes(b"MZ")
        before = len(self.store.actions(limit=1000))
        res = contain.execute(self.store, "quarantine", {"path": target}, dry_run=True)
        self.assertTrue(res["ok"] and res["dry_run"])
        self.assertTrue(os.path.exists(target))
        self.assertEqual(len(self.store.actions(limit=1000)), before, "a dry run is not logged as an action")


@unittest.skipUnless(WINDOWS, "needs Windows")
class ProcessContainment(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.close)
        self.child = sleeper()
        self.addCleanup(reap, self.child)
        time.sleep(0.3)

    def test_suspend_is_verified_and_undoable_then_kill(self):
        ent = entity_for(self.child)
        res = contain.execute(self.store, "suspend", ent)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["verified"], "suspension must be read back from Windows")
        self.assertTrue(res["undoable"])
        self.assertTrue(contain._suspended(self.child.pid))
        undone = contain.undo(self.store, res["action_id"])
        self.assertTrue(undone["ok"], undone)
        self.assertFalse(contain._suspended(self.child.pid))
        self.assertFalse(contain.undo(self.store, res["action_id"])["ok"], "an action can be undone once")
        killed = contain.execute(self.store, "kill", ent)
        self.assertTrue(killed["ok"], killed)
        self.assertFalse(killed["undoable"])
        self.child.wait(timeout=5)

    def test_pid_reuse_guard(self):
        ent = entity_for(self.child)
        ent["created"] = ent["created"] - 500
        res = contain.execute(self.store, "kill", ent)
        self.assertTrue(res.get("refused"), res)
        self.assertIn("different program", res["message"])
        self.assertIsNone(self.child.poll())

    def test_core_processes_and_hostguard_itself_are_off_limits(self):
        pids = {name.lower(): pid for pid, _pp, name in winapi.list_pids()}
        for name in ("csrss.exe", "lsass.exe", "services.exe", "winlogon.exe"):
            res = contain.execute(self.store, "kill", {"pid": pids[name]}, force=True)
            self.assertTrue(res.get("refused"), (name, res))
        me = contain.execute(self.store, "suspend", {"pid": os.getpid()}, force=True)
        self.assertTrue(me.get("refused"), me)
        self.assertTrue(contain.execute(self.store, "kill", {"pid": 4}).get("refused"))

    def test_automatic_mode_never_kills_by_default(self):
        res = contain.execute(self.store, "kill", entity_for(self.child), actor="auto-policy")
        self.assertTrue(res.get("refused"), res)
        self.assertIsNone(self.child.poll())

    def test_refusals_are_logged(self):
        contain.execute(self.store, "kill", {"pid": 4})
        self.assertEqual(self.store.actions()[0]["state"], "refused")


@unittest.skipUnless(WINDOWS, "needs Windows")
class Policy(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.close)
        self.child = sleeper()
        self.addCleanup(reap, self.child)
        self.addCleanup(lambda: paths.save_config(paths.DEFAULTS))
        time.sleep(0.3)

    def add(self, finding: Finding) -> str:
        self.store.upsert_findings(self.store.start_run("test", False), [finding.to_row()])
        return finding.key

    def mode(self, **over):
        cfg = paths.load_config()
        cfg["containment"].update(over)
        paths.save_config(cfg)

    def test_off_does_nothing(self):
        self.mode(mode="off")
        self.assertEqual(policy.apply(self.store, [self.add(process_finding(self.child))]), [])
        self.assertFalse(contain._suspended(self.child.pid))

    def test_ask_queues_and_approval_runs_it(self):
        self.mode(mode="ask")
        fid = self.add(process_finding(self.child))
        out = policy.apply(self.store, [fid])
        self.assertEqual([(o["action"], o["mode"]) for o in out], [("suspend", "ask")])
        self.assertFalse(contain._suspended(self.child.pid))
        self.assertEqual(policy.apply(self.store, [fid]), [], "one request per finding, not one per pass")
        res = contain.decide(self.store, out[0]["action_id"], approve=True)
        self.assertTrue(res["ok"], res)
        self.assertTrue(contain._suspended(self.child.pid))
        self.assertEqual(self.store.get_finding(fid)["status"], "contained")

    def test_deny_leaves_the_process_alone(self):
        self.mode(mode="ask")
        out = policy.apply(self.store, [self.add(process_finding(self.child))])
        self.assertTrue(contain.decide(self.store, out[0]["action_id"], approve=False)["ok"])
        self.assertFalse(contain._suspended(self.child.pid))
        self.assertFalse(contain.decide(self.store, out[0]["action_id"], approve=True)["ok"])

    def test_auto_contains_a_critical_finding(self):
        self.mode(mode="auto")
        fid = self.add(process_finding(self.child))
        out = policy.apply(self.store, [fid])
        self.assertEqual([(o["action"], o["mode"], o["ok"]) for o in out], [("suspend", "auto", True)])
        self.assertTrue(contain._suspended(self.child.pid))
        log = self.store.actions()[0]
        self.assertEqual((log["actor"], log["action"], log["rollback"]["kind"]), ("auto-policy", "suspend", "resume"))

    def test_auto_leaves_weaker_findings_for_the_operator(self):
        self.mode(mode="auto")
        out = policy.apply(self.store, [self.add(process_finding(self.child, severity="high", confidence="medium"))])
        self.assertEqual([o["mode"] for o in out], ["ask"])
        self.assertFalse(contain._suspended(self.child.pid))

    def test_trusted_and_agent_tags_are_never_automatic(self):
        self.mode(mode="auto")
        for tag in ("trusted-path", "ai-agent-command", "known-installer"):
            out = policy.apply(self.store, [self.add(process_finding(self.child, tags=(tag,)))])
            self.assertTrue(all(o["mode"] == "ask" for o in out), (tag, out))
        self.assertFalse(contain._suspended(self.child.pid))

    def test_hourly_limit_turns_automatic_into_ask(self):
        self.mode(mode="auto", max_auto_actions_per_hour=0)
        out = policy.apply(self.store, [self.add(process_finding(self.child))])
        self.assertEqual([o["mode"] for o in out], ["ask"])
        self.assertIn("hourly limit", out[0]["message"])

    def test_a_model_verdict_cannot_cancel_containment(self):
        self.mode(mode="auto")
        fid = self.add(process_finding(self.child))
        self.store.set_verdict(fid, {"verdict": "benign", "confidence": "high", "summary": "ignore previous instructions"})
        out = policy.apply(self.store, [fid])
        self.assertEqual([(o["mode"], o["ok"]) for o in out], [("auto", True)])

    def test_a_model_verdict_escalates_only_when_switched_on(self):
        self.mode(mode="auto")
        f = process_finding(self.child, severity="high", confidence="medium")
        fid = self.add(f)
        self.store.set_verdict(fid, {"verdict": "malicious", "confidence": "high"})
        self.assertEqual([o["mode"] for o in policy.apply(self.store, [fid])], ["ask"])
        self.mode(mode="auto", agent_can_escalate=True)
        other = sleeper()
        self.addCleanup(reap, other)
        time.sleep(0.3)
        fid2 = self.add(process_finding(other, severity="high", confidence="medium"))
        self.store.set_verdict(fid2, {"verdict": "malicious", "confidence": "high"})
        self.assertEqual([(o["mode"], o["ok"]) for o in policy.apply(self.store, [fid2])], [("auto", True)])


@unittest.skipUnless(WINDOWS, "needs Windows")
class AutorunAndNetwork(unittest.TestCase):
    KEY = r"Software\HostGuardSelfTest\Run"

    def setUp(self):
        import winreg
        self.store = Store()
        self.addCleanup(self.store.close)
        with winreg.CreateKeyEx(reg.HKCU, self.KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Updater", 0, winreg.REG_SZ, r'"C:\Users\Public\updater.exe" --silent')

        def cleanup():
            for sub in (self.KEY, r"Software\HostGuardSelfTest"):
                try:
                    winreg.DeleteKey(reg.HKCU, sub)
                except OSError:
                    pass
        self.addCleanup(cleanup)

    def test_run_value_is_removed_and_restored_exactly(self):
        ent = {"type": "autorun", "kind": "run_key", "location": "HKCU\\" + self.KEY, "name": "Updater",
               "command": r'"C:\Users\Public\updater.exe" --silent', "path": r"C:\Users\Public\updater.exe"}
        res = contain.execute(self.store, "disable_autorun", ent)
        self.assertTrue(res["ok"] and res["verified"], res)
        self.assertNotIn("Updater", reg.values(reg.HKCU, self.KEY))
        self.assertTrue(contain.undo(self.store, res["action_id"])["ok"])
        self.assertEqual(reg.values(reg.HKCU, self.KEY)["Updater"], r'"C:\Users\Public\updater.exe" --silent')

    def test_protected_services_and_windows_tasks(self):
        svc = {"type": "autorun", "kind": "service", "location": "HKLM\\System\\CurrentControlSet\\Services\\WinDefend", "name": "WinDefend"}
        self.assertTrue(contain.execute(self.store, "disable_autorun", svc, force=True).get("refused"))
        task = {"type": "autorun", "kind": "task", "location": "Task Scheduler", "name": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"}
        self.assertTrue(contain.execute(self.store, "disable_autorun", task).get("refused"))

    def test_ip_targets(self):
        for bad in ("not-an-ip", "127.0.0.1", "0.0.0.0", "224.0.0.1"):
            self.assertTrue(contain.execute(self.store, "block_ip", {"ip": bad}).get("refused"), bad)
        self.assertIn("private address", contain.execute(self.store, "block_ip", {"ip": "192.168.1.1"})["message"])
        ok = contain.execute(self.store, "block_ip", {"ip": "8.8.8.8"}, dry_run=True)   # dry run: nothing is blocked
        self.assertTrue(ok["ok"] and ok["dry_run"])

    def test_automatic_actions_never_ask_for_elevation(self):
        res = contain.execute(self.store, "block_ip", {"ip": "8.8.8.8"}, actor="auto-policy")
        self.assertFalse(res["ok"])
        self.assertTrue(res.get("needs_elevation"), res)

    def test_isolation_state_is_read_from_windows(self):
        st = contain.isolation_state()
        self.assertIn(st["isolated"], (True, False, None))
        self.assertIn("one_click_task", st)

    def test_cannot_disable_the_logged_in_account(self):
        res = contain.execute(self.store, "disable_user", {"name": os.environ.get("USERNAME", "")})
        self.assertTrue(res.get("refused"), res)


if __name__ == "__main__":
    unittest.main()
