"""Thin ctypes wrappers over the Win32 calls HostGuard needs.

Everything here is read-only except suspend_process / resume_process / terminate_process.
On a non-Windows host the module imports but every call raises NotSupported, so the rule and
policy code can still be unit-tested anywhere.
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import time
from dataclasses import asdict, dataclass

IS_WINDOWS = os.name == "nt"


class NotSupported(RuntimeError):
    pass


PROCESS_TERMINATE = 0x0001
PROCESS_VM_READ = 0x0010
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
THREAD_QUERY_INFORMATION = 0x0040
TOKEN_QUERY = 0x0008

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
EXEC_PROTECTIONS = (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

TCP_STATES = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1",
              7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}

_INTEGRITY = [(0x4000, "system"), (0x3000, "high"), (0x2000, "medium"), (0x1000, "low"), (0, "untrusted")]

if IS_WINDOWS:
    import ctypes.wintypes as wt

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _iphlp = ctypes.WinDLL("iphlpapi")
    _shell32 = ctypes.WinDLL("shell32")

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD),
                    ("szExeFile", wt.WCHAR * 260)]

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                    ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", wt.LONG), ("tpDeltaPri", wt.LONG),
                    ("dwFlags", wt.DWORD)]

    class _UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wt.USHORT), ("MaximumLength", wt.USHORT), ("Buffer", ctypes.c_void_p)]

    class _MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t),
                    ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

    class _FILETIME(ctypes.Structure):
        _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]

    class _TCPROW(ctypes.Structure):
        _fields_ = [("state", wt.DWORD), ("laddr", wt.DWORD), ("lport", wt.DWORD), ("raddr", wt.DWORD),
                    ("rport", wt.DWORD), ("pid", wt.DWORD)]

    class _TCP6ROW(ctypes.Structure):
        _fields_ = [("laddr", ctypes.c_ubyte * 16), ("lscope", wt.DWORD), ("lport", wt.DWORD),
                    ("raddr", ctypes.c_ubyte * 16), ("rscope", wt.DWORD), ("rport", wt.DWORD),
                    ("state", wt.DWORD), ("pid", wt.DWORD)]

    class _UDPROW(ctypes.Structure):
        _fields_ = [("laddr", wt.DWORD), ("lport", wt.DWORD), ("pid", wt.DWORD)]

    class _UDP6ROW(ctypes.Structure):
        _fields_ = [("laddr", ctypes.c_ubyte * 16), ("lscope", wt.DWORD), ("lport", wt.DWORD), ("pid", wt.DWORD)]

    _k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    _k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    _k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _k32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _k32.OpenProcess.restype = wt.HANDLE
    _k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    _k32.OpenThread.restype = wt.HANDLE
    _k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    _k32.CloseHandle.argtypes = [wt.HANDLE]
    _k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    _k32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(_FILETIME)] * 4
    _k32.CreateFileW.restype = wt.HANDLE
    _k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    _k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
    _k32.ProcessIdToSessionId.argtypes = [wt.DWORD, ctypes.POINTER(wt.DWORD)]
    _k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
    _k32.VirtualQueryEx.restype = ctypes.c_size_t
    _k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(_MBI), ctypes.c_size_t]
    _k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
    _ntdll.NtQueryInformationProcess.restype = ctypes.c_long
    _ntdll.NtQueryInformationProcess.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.ULONG,
                                                 ctypes.POINTER(wt.ULONG)]
    _ntdll.NtQueryInformationThread.restype = ctypes.c_long
    _ntdll.NtQueryInformationThread.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.ULONG,
                                                ctypes.POINTER(wt.ULONG)]
    _ntdll.NtSuspendProcess.restype = ctypes.c_long
    _ntdll.NtSuspendProcess.argtypes = [wt.HANDLE]
    _ntdll.NtResumeProcess.restype = ctypes.c_long
    _ntdll.NtResumeProcess.argtypes = [wt.HANDLE]
    _adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    _adv.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD,
                                         ctypes.POINTER(wt.DWORD)]
    _adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    _adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    _adv.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
    _adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]
    _adv.LookupAccountSidW.argtypes = [wt.LPCWSTR, ctypes.c_void_p, wt.LPWSTR, ctypes.POINTER(wt.DWORD),
                                       wt.LPWSTR, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD)]
    _iphlp.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL, wt.ULONG,
                                           ctypes.c_int, wt.ULONG]
    _iphlp.GetExtendedUdpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL, wt.ULONG,
                                           ctypes.c_int, wt.ULONG]


def _need_windows() -> None:
    if not IS_WINDOWS:
        raise NotSupported("this call needs Windows")


@dataclass
class Proc:
    pid: int
    ppid: int
    name: str
    path: str | None = None
    cmdline: str | None = None
    created: float | None = None      # epoch seconds
    session: int | None = None
    user: str | None = None
    integrity: str | None = None      # low / medium / high / system
    accessible: bool = False          # could we open it (False for most SYSTEM processes when not elevated)

    def to_dict(self) -> dict:
        return asdict(self)


def message_box(title: str, text: str, error: bool = False) -> None:
    """A plain Windows message box, for the windowless shortcut that has no console to print to."""
    if not IS_WINDOWS:
        return
    try:
        # icon (error or information) | bring to the foreground
        ctypes.WinDLL("user32").MessageBoxW(None, str(text), str(title), (0x10 if error else 0x40) | 0x10000)
    except OSError:
        pass


def is_elevated() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return bool(_shell32.IsUserAnAdmin())
    except OSError:
        return False


def current_pid() -> int:
    return os.getpid()


def _ft_to_epoch(ft) -> float | None:
    v = (ft.hi << 32) | ft.lo
    return (v - 116444736000000000) / 1e7 if v else None


def _image(h) -> str | None:
    buf = ctypes.create_unicode_buffer(32768)
    n = wt.DWORD(32768)
    return buf.value if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None


def _cmdline(h) -> str | None:
    """ProcessCommandLineInformation (60): works with a limited-query handle on Windows 8.1 and later."""
    size = wt.ULONG(0)
    _ntdll.NtQueryInformationProcess(h, 60, None, 0, ctypes.byref(size))
    if not size.value:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if _ntdll.NtQueryInformationProcess(h, 60, buf, size.value, ctypes.byref(size)) != 0:
        return None
    us = _UNICODE_STRING.from_buffer(buf)
    if not us.Buffer or not us.Length:
        return ""
    return ctypes.wstring_at(us.Buffer, us.Length // 2)


def _token_info(h) -> tuple[str | None, str | None]:
    """(DOMAIN\\user, integrity level) of a process handle, or Nones."""
    tok = wt.HANDLE()
    if not _adv.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(tok)):
        return None, None
    user = integ = None
    try:
        size = wt.DWORD(0)
        _adv.GetTokenInformation(tok, 1, None, 0, ctypes.byref(size))  # TokenUser
        if size.value:
            buf = ctypes.create_string_buffer(size.value)
            if _adv.GetTokenInformation(tok, 1, buf, size.value, ctypes.byref(size)):
                sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
                name = ctypes.create_unicode_buffer(256)
                dom = ctypes.create_unicode_buffer(256)
                nlen, dlen, use = wt.DWORD(256), wt.DWORD(256), wt.DWORD(0)
                if _adv.LookupAccountSidW(None, sid, name, ctypes.byref(nlen), dom, ctypes.byref(dlen),
                                          ctypes.byref(use)):
                    user = f"{dom.value}\\{name.value}" if dom.value else name.value
        size = wt.DWORD(0)
        _adv.GetTokenInformation(tok, 25, None, 0, ctypes.byref(size))  # TokenIntegrityLevel
        if size.value:
            buf = ctypes.create_string_buffer(size.value)
            if _adv.GetTokenInformation(tok, 25, buf, size.value, ctypes.byref(size)):
                sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
                count = _adv.GetSidSubAuthorityCount(sid)[0]
                rid = _adv.GetSidSubAuthority(sid, count - 1)[0]
                integ = next(name for floor, name in _INTEGRITY if rid >= floor)
    finally:
        _k32.CloseHandle(tok)
    return user, integ


def list_pids() -> list[tuple[int, int, str]]:
    """(pid, parent pid, image name) for every process. Cheap: about 10 ms."""
    _need_windows()
    snap = _k32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == wt.HANDLE(-1).value:
        return []
    out = []
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        ok = _k32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            out.append((pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile))
            ok = _k32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        _k32.CloseHandle(snap)
    return out


def describe_process(pid: int, ppid: int = 0, name: str = "", with_token: bool = True) -> Proc:
    _need_windows()
    p = Proc(pid=pid, ppid=ppid, name=name)
    sid = wt.DWORD(0)
    if _k32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
        p.session = sid.value
    if pid in (0, 4):
        return p
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return p
    try:
        p.accessible = True
        p.path = _image(h)
        p.cmdline = _cmdline(h)
        c, e, k, u = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
        if _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            p.created = _ft_to_epoch(c)
        if with_token:
            p.user, p.integrity = _token_info(h)
    finally:
        _k32.CloseHandle(h)
    return p


def list_processes(with_token: bool = True) -> list[Proc]:
    return [describe_process(pid, ppid, name, with_token) for pid, ppid, name in list_pids()]


def process_created(pid: int) -> float | None:
    """Creation time of a live process, used to make sure a PID still means the same process."""
    _need_windows()
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        c, e, k, u = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
        if _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return _ft_to_epoch(c)
    finally:
        _k32.CloseHandle(h)
    return None


def process_alive(pid: int) -> bool:
    if not IS_WINDOWS:
        return False
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ctypes.get_last_error() == 5  # access denied still means it exists
    try:
        code = wt.DWORD(0)
        if not _k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return False
        return code.value == 259  # STILL_ACTIVE
    finally:
        _k32.CloseHandle(h)


# ------------------------------------------------------------------ network

def _port(v: int) -> int:
    return socket.ntohs(v & 0xFFFF)


def _table(fn, family: int, cls: int, row_type) -> list:
    size = wt.DWORD(0)
    fn(None, ctypes.byref(size), False, family, cls, 0)
    for _ in range(4):  # the table can grow between the sizing call and the real one
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = wt.DWORD(len(buf))
        if fn(buf, ctypes.byref(size), False, family, cls, 0) == 0:
            n = struct.unpack_from("I", buf, 0)[0]
            offset = max(4, ctypes.alignment(row_type))
            return list((row_type * n).from_buffer_copy(buf, offset))
    return []


def connections() -> list[dict]:
    """Every TCP connection and listener, and every UDP listener, with the owning PID."""
    _need_windows()
    out: list[dict] = []
    for r in _table(_iphlp.GetExtendedTcpTable, socket.AF_INET, 5, _TCPROW):
        out.append({"proto": "tcp", "state": TCP_STATES.get(r.state, str(r.state)),
                    "laddr": socket.inet_ntoa(struct.pack("<I", r.laddr)), "lport": _port(r.lport),
                    "raddr": socket.inet_ntoa(struct.pack("<I", r.raddr)), "rport": _port(r.rport), "pid": r.pid})
    for r in _table(_iphlp.GetExtendedTcpTable, socket.AF_INET6, 5, _TCP6ROW):
        out.append({"proto": "tcp", "state": TCP_STATES.get(r.state, str(r.state)),
                    "laddr": socket.inet_ntop(socket.AF_INET6, bytes(r.laddr)), "lport": _port(r.lport),
                    "raddr": socket.inet_ntop(socket.AF_INET6, bytes(r.raddr)), "rport": _port(r.rport),
                    "pid": r.pid})
    for r in _table(_iphlp.GetExtendedUdpTable, socket.AF_INET, 1, _UDPROW):
        out.append({"proto": "udp", "state": "LISTEN", "laddr": socket.inet_ntoa(struct.pack("<I", r.laddr)),
                    "lport": _port(r.lport), "raddr": "", "rport": 0, "pid": r.pid})
    for r in _table(_iphlp.GetExtendedUdpTable, socket.AF_INET6, 1, _UDP6ROW):
        out.append({"proto": "udp", "state": "LISTEN", "laddr": socket.inet_ntop(socket.AF_INET6, bytes(r.laddr)),
                    "lport": _port(r.lport), "raddr": "", "rport": 0, "pid": r.pid})
    for c in out:
        if c["state"] == "LISTEN":
            c["raddr"], c["rport"] = "", 0
    return out


# ------------------------------------------------------------------ containment primitives

def _open(pid: int, access: int):
    h = _k32.OpenProcess(access, False, pid)
    if not h:
        err = ctypes.get_last_error()
        raise OSError(err, "access denied (needs administrator)" if err == 5 else ctypes.FormatError(err))
    return h


def suspend_process(pid: int) -> None:
    _need_windows()
    h = _open(pid, PROCESS_SUSPEND_RESUME)
    try:
        st = _ntdll.NtSuspendProcess(h)
        if st != 0:
            raise OSError(f"NtSuspendProcess failed (status {st & 0xFFFFFFFF:#x})")
    finally:
        _k32.CloseHandle(h)


def resume_process(pid: int) -> None:
    _need_windows()
    h = _open(pid, PROCESS_SUSPEND_RESUME)
    try:
        st = _ntdll.NtResumeProcess(h)
        if st != 0:
            raise OSError(f"NtResumeProcess failed (status {st & 0xFFFFFFFF:#x})")
    finally:
        _k32.CloseHandle(h)


def is_suspended(pid: int) -> bool | None:
    """True when every thread of the process has a suspend count above zero. None if it can't be told.

    A thread that was blocked in the kernel when it was suspended keeps showing its old wait reason,
    so the thread state is not a reliable sign; the suspend count is.
    """
    _need_windows()
    tids = thread_ids(pid).get(pid, [])
    if not tids:
        return None
    for tid in tids:
        th = _k32.OpenThread(0x0800, False, tid)  # THREAD_QUERY_LIMITED_INFORMATION
        if not th:
            return None
        try:
            count = wt.ULONG(0)
            if _ntdll.NtQueryInformationThread(th, 35, ctypes.byref(count), ctypes.sizeof(count), None) != 0:
                return None  # ThreadSuspendCount needs Windows 8.1 or later
        finally:
            _k32.CloseHandle(th)
        if count.value == 0:
            return False
    return True


def terminate_process(pid: int) -> None:
    _need_windows()
    h = _open(pid, PROCESS_TERMINATE)
    try:
        if not _k32.TerminateProcess(h, 1):
            err = ctypes.get_last_error()
            raise OSError(err, ctypes.FormatError(err))
    finally:
        _k32.CloseHandle(h)


# ------------------------------------------------------------------ memory inspection (read-only)

def thread_ids(pid: int | None = None) -> dict[int, list[int]]:
    """{pid: [thread ids]} from one snapshot."""
    _need_windows()
    snap = _k32.CreateToolhelp32Snapshot(0x4, 0)
    out: dict[int, list[int]] = {}
    if not snap or snap == wt.HANDLE(-1).value:
        return out
    try:
        te = _THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        ok = _k32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if pid is None or te.th32OwnerProcessID == pid:
                out.setdefault(te.th32OwnerProcessID, []).append(te.th32ThreadID)
            ok = _k32.Thread32Next(snap, ctypes.byref(te))
    finally:
        _k32.CloseHandle(snap)
    return out


def _query(h, addr: int):
    mbi = _MBI()
    if not _k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        return None
    return mbi


def _read(h, addr: int, n: int) -> bytes:
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not _k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return b""
    return buf.raw[:got.value]


def inspect_memory(pid: int, tids: list[int], max_regions: int = 200000) -> dict:
    """Two injection indicators for one process, without changing it:

    - threads whose start address is in memory that no file on disk backs (private or mapped,
      not an image): how injected shellcode and reflectively loaded DLLs usually run.
    - private (not file-backed) executable regions that begin with a PE header: a manually
      mapped module.

    Raises OSError when the process can't be opened for reading.
    """
    _need_windows()
    h = _open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    result: dict = {"unbacked_threads": [], "private_pe": [], "rwx_private": 0}
    try:
        for tid in tids:
            th = _k32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
            if not th:
                continue
            try:
                start = ctypes.c_void_p(0)
                if _ntdll.NtQueryInformationThread(th, 9, ctypes.byref(start), ctypes.sizeof(start), None) != 0:
                    continue
            finally:
                _k32.CloseHandle(th)
            if not start.value:
                continue
            mbi = _query(h, start.value)
            if mbi is None or mbi.State != MEM_COMMIT or mbi.Type == MEM_IMAGE:
                continue
            head = _read(h, mbi.AllocationBase or mbi.BaseAddress or 0, 2)
            result["unbacked_threads"].append({
                "tid": tid, "start": f"{start.value:#x}", "protect": f"{mbi.Protect:#x}",
                "type": "private" if mbi.Type == MEM_PRIVATE else "mapped", "pe_header": head == b"MZ"})
        addr, seen = 0x10000, 0
        while seen < max_regions:
            mbi = _query(h, addr)
            if mbi is None or not mbi.RegionSize:
                break
            seen += 1
            base = mbi.BaseAddress or 0
            prot = mbi.Protect & 0xFF
            if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and prot in EXEC_PROTECTIONS \
                    and not mbi.Protect & PAGE_GUARD:
                if prot == PAGE_EXECUTE_READWRITE:
                    result["rwx_private"] += 1
                head = _read(h, base, 0x400)
                if head[:2] == b"MZ" and len(head) >= 0x40:
                    lfanew = struct.unpack_from("<I", head, 0x3C)[0]
                    if lfanew < len(head) - 4 and head[lfanew:lfanew + 4] == b"PE\x00\x00":
                        result["private_pe"].append({"base": f"{base:#x}", "size": mbi.RegionSize,
                                                     "protect": f"{mbi.Protect:#x}"})
            nxt = base + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
    finally:
        _k32.CloseHandle(h)
    return result


def _write_handle_ok(path: str, access: int, flags: int) -> bool | None:
    h = _k32.CreateFileW(path, access, 0x7, None, 3, flags, None)  # share all, OPEN_EXISTING
    if h and h != wt.HANDLE(-1).value:
        _k32.CloseHandle(h)
        return True
    err = ctypes.get_last_error()
    if err in (32, 33, 1224):   # in use: the permission check passed before the sharing check failed
        return True
    if err == 5:
        return False
    return None


def can_replace(path: str) -> bool:
    """Could this (unelevated) process overwrite the file or drop another one in its folder?

    Opens handles with write access and closes them again; nothing is written. Folder names only
    hint at this (ProgramData is writable by default, but Defender's folders inside it are not),
    so rules that claim "any program can replace this" ask here first.
    """
    if not IS_WINDOWS or not path:
        return False
    file_ok = _write_handle_ok(path, 0x0002 | 0x0004, 0)                       # write data, append data
    folder_ok = _write_handle_ok(os.path.dirname(path), 0x0002, 0x02000000)    # add file, backup semantics
    return bool(file_ok) or bool(folder_ok)


def read_zone_identifier(path: str) -> dict | None:
    """Mark-of-the-Web for a file: {zone, host_url, referrer_url}, or None when it has none."""
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            text = f.read(4096)
    except OSError:
        return None
    out: dict = {}
    for line in text.splitlines():
        k, _, v = line.partition("=")
        k = k.strip().lower()
        if k == "zoneid":
            try:
                out["zone"] = int(v.strip())
            except ValueError:
                pass
        elif k == "hosturl":
            out["host_url"] = v.strip()[:500]
        elif k == "referrerurl":
            out["referrer_url"] = v.strip()[:500]
    return out or None


def now() -> float:
    return time.time()
