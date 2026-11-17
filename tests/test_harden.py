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
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-harden-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import harden, util  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
