"""A small parser for Windows shortcut (.lnk) files: target, arguments, working folder, icon.

Shortcuts matter twice: a file in a Startup folder is an autorun, and a shortcut whose target is
a script host with a long argument string is a standard phishing attachment.
"""

from __future__ import annotations

import struct

_HAS_IDLIST, _HAS_LINKINFO, _HAS_NAME, _HAS_RELPATH, _HAS_WORKDIR = 0x1, 0x2, 0x4, 0x8, 0x10
_HAS_ARGS, _HAS_ICON, _IS_UNICODE = 0x20, 0x40, 0x80
_ENV_BLOCK = 0xA0000001


def _cstr(data: bytes, off: int, wide: bool = False) -> str:
    if off <= 0 or off >= len(data):
        return ""
    if wide:
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[off:end].decode("utf-16-le", "replace")
    end = data.find(b"\x00", off)
    return data[off:end if end >= 0 else len(data)].decode("mbcs" if hasattr(bytes, "decode") else "latin-1", "replace")


def parse(path: str, max_bytes: int = 1 << 20) -> dict | None:
    """{target, args, workdir, icon, name} or None when the file is not a readable shortcut."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return None
    return parse_bytes(data)


def parse_bytes(data: bytes) -> dict | None:
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    out = {"target": "", "args": "", "workdir": "", "icon": "", "name": "", "relative": ""}
    pos = 0x4C
    try:
        if flags & _HAS_IDLIST:
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        if flags & _HAS_LINKINFO:
            size, header, lflags, _vol, local_off, _net, suffix_off = struct.unpack_from("<7I", data, pos)
            info = data[pos:pos + size]
            base = suffix = ""
            if header >= 0x24:
                local_w, suffix_w = struct.unpack_from("<2I", info, 0x1C)
                if lflags & 1 and local_w:
                    base = _cstr(info, local_w, wide=True)
                if suffix_w:
                    suffix = _cstr(info, suffix_w, wide=True)
            if not base and lflags & 1:
                base = _cstr(info, local_off)
            if not suffix:
                suffix = _cstr(info, suffix_off)
            out["target"] = base + suffix
            pos += size
        for flag, key in ((_HAS_NAME, "name"), (_HAS_RELPATH, "relative"), (_HAS_WORKDIR, "workdir"),
                          (_HAS_ARGS, "args"), (_HAS_ICON, "icon")):
            if not flags & flag:
                continue
            count = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if flags & _IS_UNICODE:
                out[key] = data[pos:pos + count * 2].decode("utf-16-le", "replace")
                pos += count * 2
            else:
                out[key] = data[pos:pos + count].decode("latin-1", "replace")
                pos += count
        while pos + 8 <= len(data):  # extra data blocks
            size, sig = struct.unpack_from("<II", data, pos)
            if size < 4:
                break
            if sig == _ENV_BLOCK and size >= 0x314 and not out["target"]:
                wide = data[pos + 8 + 260:pos + 8 + 260 + 520].decode("utf-16-le", "replace").split("\x00", 1)[0]
                out["target"] = wide or data[pos + 8:pos + 8 + 260].split(b"\x00", 1)[0].decode("latin-1", "replace")
            pos += size
    except (struct.error, IndexError):
        pass
    if not out["target"] and out["relative"]:
        out["target"] = out["relative"]
    return out
