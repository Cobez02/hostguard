"""HostGuard as an application: the launcher, the packaging file, the shortcuts and the windowless command."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-app-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import __version__, cli, paths, scan, shortcuts, ui, util, winapi  # noqa: E402

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=120, creationflags=NO_WINDOW, stdin=subprocess.DEVNULL, **kw)


class Launcher(unittest.TestCase):
    def test_background_processes_are_started_through_the_launcher(self):
        cmd = paths.background_command("monitor", "run")
        self.assertEqual(cmd[1:], [str(paths.LAUNCHER), "monitor", "run"])
        self.assertTrue(paths.LAUNCHER.is_file())
        self.assertTrue(os.path.isfile(cmd[0]))
        self.assertEqual(ui._command(8930)[1:], [str(paths.LAUNCHER), "ui", "run", "--port", "8930", "--no-browser"])
        self.assertEqual(paths.OWN_DIR, ROOT, "from a source checkout, HostGuard's own folder is the whole checkout")
        self.assertIn(scan.own_marker(), str(paths.LAUNCHER).lower(), "a scan must recognise the launcher's command line as its own")

    def test_the_launcher_runs_from_any_folder(self):
        r = run([sys.executable, "-I", str(paths.LAUNCHER), "--version"], cwd=_TMP)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, f"hostguard {__version__}"), r.stderr)

    def test_an_installed_copy_works_without_the_source_folder(self):
        """What pip does, by hand: the package alone in a folder of its own, with no run.py beside it."""
        site = Path(_TMP) / "site-packages"
        shutil.copytree(ROOT / "hostguard", site / "hostguard", ignore=shutil.ignore_patterns("__pycache__"))
        launcher = site / "hostguard" / "launch.py"
        r = run([sys.executable, "-I", str(launcher), "--version"], cwd=_TMP)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, f"hostguard {__version__}"), r.stderr)
        probe = ("import json, sys; sys.path.insert(0, sys.argv[1]); from hostguard import paths, scan; "
                 "print(json.dumps({'own': str(paths.OWN_DIR), 'pkg': str(paths.PKG_DIR), 'cmd': paths.background_command('x'), "
                 "'marker': scan.own_marker(), 'ps': sorted(p.name for p in paths.PS_DIR.glob('*.ps1'))}))")
        r = run([sys.executable, "-I", "-c", probe, str(site)], cwd=_TMP)
        self.assertEqual(r.returncode, 0, r.stderr)
        got = json.loads(r.stdout)
        self.assertEqual(got["own"], got["pkg"], "installed, only the package is HostGuard's own: its parent is shared")
        self.assertEqual(Path(got["pkg"]), (site / "hostguard").resolve())
        self.assertEqual(Path(got["cmd"][1]), launcher.resolve())
        self.assertNotEqual(got["marker"], str(site.resolve()).lower(), "site-packages as the marker would hide every other installed program")
        self.assertIn("elevated.ps1", got["ps"])


class Packaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_the_commands_point_at_real_functions(self):
        project = self.meta["project"]
        self.assertEqual(project["scripts"], {"hostguard": "hostguard.cli:main"})
        self.assertEqual(project["gui-scripts"], {"hostguardw": "hostguard.cli:app_main"})
        self.assertTrue(callable(cli.main) and callable(cli.app_main))
        self.assertEqual(project["dependencies"], [], "HostGuard uses the standard library only")
        self.assertEqual(self.meta["tool"]["setuptools"]["dynamic"]["version"], {"attr": "hostguard.__version__"})
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")

    def test_every_package_and_helper_file_is_shipped(self):
        listed = set(self.meta["tool"]["setuptools"]["packages"])
        real = {".".join(p.parent.relative_to(ROOT).parts) for p in (ROOT / "hostguard").rglob("__init__.py")}
        self.assertEqual(listed, real)
        globs = self.meta["tool"]["setuptools"]["package-data"]["hostguard"]
        shipped = {p for g in globs for p in (ROOT / "hostguard").glob(g)}
        needed = {p for p in (ROOT / "hostguard").rglob("*") if p.is_file() and p.suffix not in (".py", ".pyc")}
        self.assertEqual(sorted(needed - shipped), [], "a file the code needs would be missing from an installed copy")
        self.assertTrue(shortcuts.ICON.is_file())

    def test_the_icon_is_a_real_icon(self):
        data = shortcuts.ICON.read_bytes()
        reserved, kind, count = int.from_bytes(data[0:2], "little"), int.from_bytes(data[2:4], "little"), int.from_bytes(data[4:6], "little")
        self.assertEqual((reserved, kind), (0, 1))
        sizes = {data[6 + 16 * i] or 256 for i in range(count)}
        self.assertTrue({16, 32, 48, 256} <= sizes, sizes)
        last = 6 + 16 * (count - 1)
        self.assertEqual(int.from_bytes(data[last + 8:last + 12], "little") + int.from_bytes(data[last + 12:last + 16], "little"), len(data))


@unittest.skipUnless(WINDOWS, "shortcuts are a Windows thing")
class Shortcuts(unittest.TestCase):
    def test_windows_says_where_the_folders_are(self):
        where = shortcuts.folders()
        self.assertEqual(set(where), {"desktop", "start_menu"})
        for folder in where.values():
            self.assertTrue(os.path.isdir(folder), folder)

    def test_add_read_back_and_remove(self):
        fake = {"desktop": os.path.join(_TMP, "Desk top"), "start_menu": os.path.join(_TMP, "Start Menu")}
        for folder in fake.values():
            os.makedirs(folder, exist_ok=True)
        real_folders = shortcuts.folders
        shortcuts.folders = lambda: dict(fake)
        try:
            self.assertEqual({k: v["present"] for k, v in shortcuts.status().items()}, {"desktop": False, "start_menu": False})
            res = shortcuts.add()
            self.assertTrue(res["ok"], res)
            self.assertIn("desktop", res["message"])
            link = os.path.join(fake["desktop"], shortcuts.FILE_NAME)
            self.assertTrue(os.path.isfile(link) and os.path.isfile(os.path.join(fake["start_menu"], shortcuts.FILE_NAME)))
            script = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:HG_TEST_LINK); "
                      "@{ target = $s.TargetPath; arguments = $s.Arguments; icon = $s.IconLocation; dir = $s.WorkingDirectory } | ConvertTo-Json -Compress")
            r = run([paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script], env={**os.environ, "HG_TEST_LINK": link})
            self.assertEqual(r.returncode, 0, r.stderr)
            got = json.loads(r.stdout)
            program, launcher = paths.background_command()[:2]
            self.assertEqual(os.path.normcase(got["target"]), os.path.normcase(program))
            self.assertEqual(got["arguments"], f'"{launcher}" app')
            self.assertEqual(os.path.normcase(got["icon"]), os.path.normcase(f"{shortcuts.ICON},0"))
            self.assertTrue(shortcuts.add()["ok"], "adding again refreshes the shortcuts")
            res = shortcuts.remove()
            self.assertTrue(res["ok"], res)
            self.assertFalse(os.path.exists(link))
            self.assertTrue(shortcuts.remove()["ok"], "removing what is not there is not an error")
        finally:
            shortcuts.folders = real_folders


class AppCommand(unittest.TestCase):
    """What the shortcut runs. It has no console, so anything that goes wrong must reach a message box."""

    def setUp(self):
        self.boxes = []
        self._real = (ui.open_dashboard, winapi.message_box)
        winapi.message_box = lambda title, text, error=False: self.boxes.append((title, text, error))

    def tearDown(self):
        ui.open_dashboard, winapi.message_box = self._real

    def app(self):
        with redirect_stdout(io.StringIO()):
            return cli.app_main()

    def test_opened_is_silent(self):
        ui.open_dashboard = lambda port=8930, **kw: {"ok": True, "opened": True, "message": "dashboard started"}
        self.assertEqual(self.app(), 0)
        self.assertEqual(self.boxes, [])

    def test_a_failed_start_is_shown(self):
        ui.open_dashboard = lambda port=8930, **kw: {"ok": False, "message": "port 8930 is in use by another program"}
        self.assertEqual(self.app(), 1)
        self.assertEqual(len(self.boxes), 1)
        self.assertIn("port 8930 is in use", self.boxes[0][1])
        self.assertTrue(self.boxes[0][2], "shown as an error")

    def test_no_browser_hands_over_the_link(self):
        ui.open_dashboard = lambda port=8930, **kw: {"ok": True, "opened": False, "message": "dashboard started",
                                                     "sign_in_link": "http://127.0.0.1:8930/login?k=one-time"}
        self.assertEqual(self.app(), 1)
        self.assertIn("http://127.0.0.1:8930/login?k=one-time", self.boxes[0][1])
        self.assertFalse(self.boxes[0][2])


if __name__ == "__main__":
    unittest.main()
