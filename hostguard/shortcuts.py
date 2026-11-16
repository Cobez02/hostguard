"""Desktop and Start Menu shortcuts, so HostGuard starts like any other application.

A shortcut runs the windowless Python with HostGuard's launcher and the `app` command: that opens
the dashboard and, because a windowless program has no console, reports a failure in a message box.

The shortcut file is built in the state folder first and then copied into place. A Python from the
Microsoft Store can only write a private copy of a new file under AppData, which is where the
Start Menu lives, so a copy that lands in that private place is taken back and handed to Windows'
transfer service instead (the same route a restored quarantine file takes).
"""

from __future__ import annotations

import json
import os
import shutil

from . import paths, util

FILE_NAME = "HostGuard.lnk"
ICON = paths.PKG_DIR / "assets" / "hostguard.ico"
_PS = [paths.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]


def folders() -> dict[str, str]:
    """This user's Desktop and Start Menu folders, asked from Windows: either may have been moved (OneDrive does that)."""
    rc, out, err = util.run_cmd(_PS + [str(paths.PS_DIR / "shortcut.ps1"), "-Folders"], timeout=60)
    try:
        found = json.loads(out) if rc == 0 else {}
    except ValueError:
        found = {}
    if not found.get("desktop") or not found.get("start_menu"):
        raise OSError(f"could not ask Windows where the Desktop and Start Menu are: {err.strip() or out.strip() or rc}")
    return {"desktop": str(found["desktop"]), "start_menu": str(found["start_menu"])}


def status(where: dict[str, str] | None = None) -> dict:
    where = where or folders()
    out = {}
    for name, folder in where.items():
        path = os.path.join(folder, FILE_NAME)
        out[name] = {"path": path, "present": os.path.isfile(path) and not util.is_redirected(path)}
    return out


def _place(staged: str, dest: str) -> str | None:
    """Copy the finished shortcut into place. Returns None when it is really there, else the reason it is not."""
    try:
        if os.path.exists(dest):
            os.remove(dest)
        shutil.copyfile(staged, dest)
    except OSError as e:
        return str(e)
    if not util.is_redirected(dest):
        return None
    os.remove(dest)       # a private copy only this Python can see: take it back
    rc, _out, err = util.run_cmd(_PS + [str(paths.PS_DIR / "place.ps1"), "-Source", staged, "-Destination", dest], timeout=120)
    if rc == 0 and os.path.isfile(dest) and not util.is_redirected(dest):
        return None
    return err.strip() or "this Python is sandboxed and Windows' transfer service could not place the file"


def add(command: str = "app") -> dict:
    """Create (or refresh) both shortcuts. `command` is what the shortcut asks HostGuard to do."""
    if os.name != "nt":
        return {"ok": False, "message": "shortcuts need Windows"}
    try:
        where = folders()
    except OSError as e:
        return {"ok": False, "message": str(e)}
    program, launcher = paths.background_command()[:2]
    staged = str(paths.sub("shortcuts") / FILE_NAME)
    rc, _out, err = util.run_cmd(_PS + [str(paths.PS_DIR / "shortcut.ps1"), "-Path", staged, "-Target", program, "-Script", launcher,
                                        "-ScriptArgs", command, "-Icon", str(ICON) if ICON.is_file() else "",
                                        "-Description", "HostGuard: is this PC compromised?", "-WorkingDirectory", str(paths.home())],
                                 timeout=60)
    if rc != 0 or not os.path.isfile(staged):
        return {"ok": False, "message": f"could not create the shortcut: {err.strip() or rc}"}
    problems = {name: why for name, folder in where.items() if (why := _place(staged, os.path.join(folder, FILE_NAME)))}
    state = status(where)
    done = [name.replace("_", " ") for name, s in state.items() if s["present"]]
    message = ("shortcut added to the " + " and the ".join(done)) if done else "no shortcut could be added"
    if problems:
        message += "; failed for the " + ", ".join(f"{k.replace('_', ' ')} ({v})" for k, v in problems.items())
    return {"ok": not problems and len(done) == len(where), "message": message, "shortcuts": state}


def remove() -> dict:
    try:
        where = folders()
    except OSError as e:
        return {"ok": False, "message": str(e)}
    for folder in where.values():
        try:
            os.remove(os.path.join(folder, FILE_NAME))
        except FileNotFoundError:
            pass
        except OSError as e:
            return {"ok": False, "message": f"could not remove the shortcut: {e}"}
    state = status(where)
    left = [name for name, s in state.items() if s["present"]]
    return {"ok": not left, "message": "shortcuts removed" if not left else "a shortcut is still there: " + ", ".join(left),
            "shortcuts": state}
