"""A small read-only parser for Windows executables (PE files): sections, imports, packing signs.

It never loads or runs the file. Everything is bounds-checked because the input is hostile by
assumption.
"""

from __future__ import annotations

import struct

from .util import entropy

PACKER_SECTIONS = {"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
                   ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".mpress1": "MPRESS",
                   ".mpress2": "MPRESS", ".enigma1": "Enigma", ".enigma2": "Enigma", ".petite": "Petite",
                   ".nsp0": "NsPack", ".nsp1": "NsPack", "pec2": "PECompact", ".pec2": "PECompact", ".y0da": "yoda",
                   ".taz": "PESpin", ".perplex": "Perplex", ".spack": "Simple Pack", ".svkp": "SVKP", ".winlice": "WinLicense"}

INJECTION = {"virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
             "queueuserapc", "ntqueueapcthread", "setthreadcontext", "ntunmapviewofsection", "zwunmapviewofsection",
             "ntwritevirtualmemory", "ntmapviewofsection"}
KEYLOG = {"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeyboardstate", "registerrawinputdevices"}
DOWNLOAD = {"urldownloadtofilea", "urldownloadtofilew", "urldownloadtocachefilea", "urldownloadtocachefilew",
            "internetopenurla", "internetopenurlw", "winhttpopen", "internetreadfile"}
ANTI = {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa",
        "ntsetinformationthread"}


def _cstr(data: bytes, off: int, limit: int = 256) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + limit)
    return data[off:end if end >= 0 else off + limit].decode("latin-1", "replace")


class PE:
    def __init__(self, data: bytes, full_size: int | None = None):
        self.data = data
        self.size = full_size if full_size is not None else len(data)
        self.valid = False
        self.sections: list[dict] = []
        self.imports: dict[str, list[str]] = {}
        self.is_dll = self.is_64 = self.is_driver = self.is_dotnet = False
        self.timestamp = 0
        self.has_signature = False
        self.overlay = 0
        self.exports = 0
        try:
            self._parse()
        except (struct.error, IndexError, ValueError):
            pass

    def _rva(self, rva: int) -> int:
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                return rva - s["va"] + s["raw"]
        return -1

    def _parse(self) -> None:
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            return
        lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if lfanew + 24 > len(d) or d[lfanew:lfanew + 4] != b"PE\x00\x00":
            return
        _machine, nsec, self.timestamp, _, _, optsize, chars = struct.unpack_from("<HHIIIHH", d, lfanew + 4)
        self.is_dll = bool(chars & 0x2000)
        opt = lfanew + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        self.is_64 = magic == 0x20B
        subsystem = struct.unpack_from("<H", d, opt + 68)[0]
        self.is_driver = subsystem == 1
        ddir = opt + (112 if self.is_64 else 96)
        ndir = struct.unpack_from("<I", d, ddir - 4)[0]
        dirs = [struct.unpack_from("<II", d, ddir + i * 8) for i in range(min(ndir, 16)) if ddir + i * 8 + 8 <= len(d)]
        sec = opt + optsize
        end_raw = 0
        for i in range(min(nsec, 96)):
            off = sec + i * 40
            if off + 40 > len(d):
                break
            name = d[off:off + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, va, rsize, raw = struct.unpack_from("<IIII", d, off + 8)
            flags = struct.unpack_from("<I", d, off + 36)[0]
            body = b""
            if raw < len(d):  # a sample from both ends is enough to tell packed data from code
                body = d[raw:raw + rsize] if rsize <= 524288 else d[raw:raw + 262144] + d[raw + rsize - 262144:raw + rsize]
            self.sections.append({"name": name, "va": va, "vsize": vsize, "raw": raw, "rsize": rsize,
                                  "exec": bool(flags & 0x20000000), "write": bool(flags & 0x80000000),
                                  "entropy": round(entropy(body), 2) if body else 0.0})
            end_raw = max(end_raw, raw + rsize)
        self.valid = True
        if len(dirs) > 4 and dirs[4][1]:
            self.has_signature = True
            end_raw = max(end_raw, dirs[4][0] + dirs[4][1])
        self.overlay = max(0, self.size - end_raw) if end_raw else 0
        if len(dirs) > 14 and dirs[14][0]:
            self.is_dotnet = True
        if dirs and dirs[0][0]:
            off = self._rva(dirs[0][0])
            if 0 <= off and off + 28 <= len(d):
                self.exports = struct.unpack_from("<I", d, off + 24)[0]
        if len(dirs) > 1 and dirs[1][0]:
            self._imports(dirs[1][0])

    def _imports(self, rva: int) -> None:
        d = self.data
        off = self._rva(rva)
        width, fmt, flag = (8, "<Q", 1 << 63) if self.is_64 else (4, "<I", 1 << 31)
        for _ in range(512):
            if off < 0 or off + 20 > len(d):
                return
            ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", d, off)
            if not name_rva and not iat:
                return
            dll = _cstr(d, self._rva(name_rva)).lower()
            funcs: list[str] = []
            thunk = self._rva(ilt or iat)
            for _ in range(4096):
                if thunk < 0 or thunk + width > len(d):
                    break
                val = struct.unpack_from(fmt, d, thunk)[0]
                if not val:
                    break
                if not val & flag:
                    name = _cstr(d, self._rva(val & 0x7FFFFFFF) + 2)
                    if name:
                        funcs.append(name)
                thunk += width
            if dll:
                self.imports.setdefault(dll, []).extend(funcs)
            off += 20

    def summary(self) -> dict:
        """What the rules look at, in plain data."""
        funcs = {f.lower() for fs in self.imports.values() for f in fs}
        packer = next((PACKER_SECTIONS[s["name"].lower()] for s in self.sections if s["name"].lower() in PACKER_SECTIONS), None)
        big = [s for s in self.sections if s["rsize"] >= 16384]
        high = [s for s in big if s["entropy"] >= 7.2]
        return {
            "kind": "driver" if self.is_driver else "dll" if self.is_dll else "exe", "bits": 64 if self.is_64 else 32,
            "dotnet": self.is_dotnet, "compiled": self.timestamp, "sections": [f"{s['name']}:{s['entropy']}" for s in self.sections][:12],
            "packer": packer, "high_entropy": bool(high) and len(high) * 2 >= len(big),
            "wx_section": any(s["exec"] and s["write"] for s in self.sections),
            "import_count": len(funcs), "import_dlls": sorted(self.imports)[:30],
            "injection_apis": sorted(funcs & INJECTION), "keylog_apis": sorted(funcs & KEYLOG),
            "download_apis": sorted(funcs & DOWNLOAD), "anti_debug_apis": sorted(funcs & ANTI),
            "embedded_signature": self.has_signature, "overlay_bytes": self.overlay, "exports": self.exports,
        }


def parse_file(path: str, max_bytes: int = 32 << 20) -> PE | None:
    try:
        import os
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return None
    if data[:2] != b"MZ":
        return None
    pe = PE(data, size)
    return pe if pe.valid else None


def score(s: dict) -> tuple[int, list[str]]:
    """How much a PE looks built to hide or to tamper with other programs. (points, reasons)"""
    pts, why = 0, []
    if s.get("packer"):
        pts += 2
        why.append(f"packed with {s['packer']}")
    elif s.get("high_entropy"):
        pts += 2
        why.append("most of the file is compressed or encrypted")
    if s.get("wx_section"):
        pts += 1
        why.append("has a section that is both writable and executable")
    inj = set(s.get("injection_apis") or [])
    if len(inj) >= 3 or {"writeprocessmemory", "createremotethread"} <= inj or {"ntunmapviewofsection", "setthreadcontext"} <= inj:
        pts += 3
        why.append("imports the calls used to inject code into other processes")
    if len(s.get("keylog_apis") or []) >= 2:
        pts += 2
        why.append("imports keyboard-capture calls")
    if s.get("download_apis") and not s.get("dotnet"):
        pts += 1
        why.append("can download files")
    if 0 < s.get("import_count", 0) <= 4 and not s.get("dotnet"):
        pts += 1
        why.append("imports almost nothing, as packed loaders do")
    if len(s.get("anti_debug_apis") or []) >= 3:
        pts += 1
        why.append("checks whether it is being debugged")
    return pts, why
