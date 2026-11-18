"""Hardening switches must show what Windows reports, in whatever shape Windows PowerShell reports it.

Windows PowerShell 5.1 writes some arrays to JSON as {"value": [...], "Count": n}. Read naively,
a list of attack surface reduction rules then looks like one unrecognisable object, and a switch
that Windows did turn on is shown as off and logged as a failed change.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-harden-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import contain, harden, util  # noqa: E402
from hostguard.store import Store  # noqa: E402


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


def wrapped(items):
    """An array the way Windows PowerShell 5.1 writes it after a calculated property."""
    return {"value": list(items), "Count": len(items)}


class PlainJson(unittest.TestCase):
    def test_wrapped_arrays_become_lists_at_any_depth(self):
        raw = {"prefs": {"AsrIds": wrapped(["a", "b"]), "AsrActions": wrapped([1, 2]), "PUAProtection": 1},
               "rows": [{"members": wrapped([{"name": "x", "groups": wrapped(["g"])}])}], "empty": wrapped([]),
               "one": {"value": "solo", "Count": 1}, "none": {"value": None, "Count": 0}}
        self.assertEqual(util.plain(raw), {"prefs": {"AsrIds": ["a", "b"], "AsrActions": [1, 2], "PUAProtection": 1},
                                           "rows": [{"members": [{"name": "x", "groups": ["g"]}]}], "empty": [],
                                           "one": ["solo"], "none": []})

    def test_ordinary_objects_are_left_alone(self):
        for same in ({"value": 3}, {"Count": 2}, {"value": [1], "Count": 1, "extra": True}, {"value": [1], "Count": "1"},
                     [1, "a", None], "text", 7, None):
            self.assertEqual(util.plain(same), same)


@unittest.skipUnless(WINDOWS, "the other switches are read from the Windows registry")
class SwitchesReadWindowsCorrectly(unittest.TestCase):
    def states(self, ids, actions, shape=wrapped):
        prefs = {"PUAProtection": 1, "EnableNetworkProtection": 0, "EnableControlledFolderAccess": 0, "CloudBlockLevel": 0,
                 "AsrIds": shape(ids) if ids is not None else None, "AsrActions": shape(actions) if actions is not None else None}
        answers = {"defender": {"status": {}, "prefs": prefs}, "accounts": {}, "rdpfw": []}
        real = util.run_cmd

        def fake(argv, timeout=60, input_text=None):
            if "-What" in argv:
                return 0, json.dumps(answers.get(argv[argv.index("-What") + 1], {})), ""
            return real(argv, timeout=timeout, input_text=input_text)
        util.run_cmd = fake
        try:
            return harden._states()
        finally:
            util.run_cmd = real

    def test_rules_reported_in_the_wrapped_shape_count_as_on(self):
        ids = list(harden.ASR_STANDARD) + list(harden.ASR_EXTENDED)
        st = self.states(ids, [1] * len(ids))
        self.assertEqual((st["asr_standard"], st["asr_extended"], st["pua_block"]), (True, True, True))

    def test_the_plain_shape_still_works(self):
        ids = list(harden.ASR_STANDARD)
        st = self.states(ids, [1] * len(ids), shape=list)
        self.assertEqual((st["asr_standard"], st["asr_extended"]), (True, False))

    def test_upper_case_ids_match(self):
        ids = [i.upper() for i in harden.ASR_STANDARD]
        self.assertTrue(self.states(ids, [1] * len(ids))["asr_standard"])

    def test_a_missing_or_audit_only_rule_is_not_on(self):
        ids = list(harden.ASR_STANDARD)
        self.assertFalse(self.states(ids[:-1], [1] * (len(ids) - 1))["asr_standard"], "one rule is missing")
        self.assertFalse(self.states(ids, [1] * (len(ids) - 1) + [2])["asr_standard"], "audit mode is not blocking")
        self.assertFalse(self.states(ids, [0] * len(ids))["asr_standard"])
        self.assertFalse(self.states(None, None)["asr_standard"], "no rules at all")
        self.assertFalse(self.states([], [])["asr_extended"])


class UndoingASwitch(unittest.TestCase):
    """Undo on a hardening entry of the action log. The administrator helper and Windows' answers are
    stand-ins here: no setting on this PC is touched."""

    def setUp(self):
        self.store = Store(os.path.join(_TMP, f"undo-{time.time_ns()}.db"))
        self.addCleanup(self.store.close)
        self.windows = {}             # what "Windows" reports for each switch
        self.asked = []
        self.obeys = True             # False: the helper says done and Windows keeps the setting anyway
        self.answer = {"ok": True, "declined": False, "message": "set", "changes": ["one change"]}

        def helper(verb, args=None, timeout=300, dry_run=False):
            self.asked.append((verb, dict(args or {})))
            if self.answer["ok"] and self.obeys:
                self.windows[args["setting"]] = args["on"]
            return dict(self.answer)
        for target, name, stand_in in ((harden.elevate, "run", helper), (harden, "_states", lambda: dict(self.windows))):
            patch = mock.patch.object(target, name, stand_in)
            patch.start()
            self.addCleanup(patch.stop)

    def entry(self):
        return self.store.actions(limit=1)[0]

    def test_undo_puts_the_switch_back_and_reads_windows_again(self):
        self.assertTrue(harden.set_state(self.store, "pua_block", True)["ok"])
        entry = self.entry()
        self.assertEqual((entry["action"], entry["rollback"]), ("harden:pua_block", {"kind": "harden", "setting": "pua_block", "on": False}))
        undone = contain.undo(self.store, entry["id"])
        self.assertEqual((undone["ok"], undone["message"]), (True, "Block potentially unwanted apps: now off"))
        self.assertEqual((self.asked[-1], self.windows["pua_block"]), (("harden", {"setting": "pua_block", "on": False}), False))
        self.assertEqual([(a["action"], a["state"]) for a in self.store.actions(limit=5)],
                         [("undo:harden:pua_block", "done"), ("harden:pua_block", "undone")], "one entry for the undo, and no third one")
        self.assertEqual(contain.undo(self.store, entry["id"])["message"], "that action was already undone")

    def test_turning_a_switch_off_can_be_undone_too(self):
        self.windows["rdp_off"] = True
        self.assertTrue(harden.set_state(self.store, "rdp_off", False)["ok"])
        self.assertTrue(contain.undo(self.store, self.entry()["id"])["ok"])
        self.assertEqual((self.asked[-1][1], self.windows["rdp_off"]), ({"setting": "rdp_off", "on": True}, True))

    def test_an_undo_windows_did_not_take_is_not_recorded_as_done(self):
        harden.set_state(self.store, "network_protection", True)
        entry = self.entry()
        self.obeys = False                                  # Tamper Protection or a policy keeps the setting
        undone = contain.undo(self.store, entry["id"])
        self.assertFalse(undone["ok"])
        self.assertIn("Windows still reports", undone["message"])
        self.assertEqual((self.store.get_action(entry["id"])["undone"], self.store.get_action(entry["id"])["state"]), (None, "done"))
        self.answer = {"ok": False, "declined": True, "message": "administrator access was declined, so nothing was changed"}
        self.assertTrue(contain.undo(self.store, entry["id"]).get("declined"))
        self.assertEqual(self.store.get_action(entry["id"])["state"], "done")
        self.assertEqual(len(self.store.actions(limit=5)), 1, "a failed undo leaves no entry of its own")

    def test_a_switch_with_no_way_back_has_nothing_to_undo(self):
        self.assertEqual(harden.ONE_WAY, {"sysmon"})
        self.assertTrue(harden.set_state(self.store, "sysmon", True)["ok"])
        entry = self.entry()
        self.assertEqual(entry["rollback"], {})
        self.assertIn("cannot be undone", contain.undo(self.store, entry["id"])["message"])
        self.assertEqual(len(self.asked), 1)
        older = self.store.log_action("operator", "harden:sysmon", {"type": "setting", "name": "sysmon", "on": True}, None, state="done",
                                      ok=True, result={"message": "x"}, rollback={"kind": "harden", "setting": "sysmon", "on": False})
        refused = contain.undo(self.store, older)             # an entry as older versions recorded it, with a way back that never existed
        self.assertEqual((refused["ok"], "cannot be undone" in refused["message"]), (False, True))
        self.assertEqual((len(self.asked), self.store.get_action(older)["state"]), (1, "done"), "Windows is not asked for what the helper would refuse")

    def test_an_entry_naming_a_switch_that_does_not_exist_changes_nothing(self):
        bogus = self.store.log_action("operator", "harden:x", {"type": "setting", "name": "x"}, None, state="done", ok=True,
                                      result={"message": "x"}, rollback={"kind": "harden", "setting": "no_such_switch", "on": False})
        res = contain.undo(self.store, bogus)
        self.assertEqual((res["ok"], self.asked), (False, []))
        self.assertIn("unknown setting", res["message"])


if __name__ == "__main__":
    unittest.main()
