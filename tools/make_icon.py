"""Draws HostGuard's icon, a shield with a check mark, and writes it out:

    hostguard/assets/hostguard.ico    the icon the shortcuts use (16 to 256 pixels)
    docs/hostguard.png                the same picture at 256 pixels, for the README

Standard library only, so anyone can rebuild the binary files in the repository and compare them:

    python tools/make_icon.py
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIZES = (16, 20, 24, 32, 40, 48, 64, 256)
TOP, BOTTOM = (0x3D, 0x7B, 0xF2), (0x1B, 0x45, 0xB5)      # the shield's blue, lighter at the top
MARK = (255, 255, 255)
MARK_WIDTH = 2.3                                          # in grid units


def cubic(p0, p1, p2, p3, steps=14):
    out = []
    for i in range(1, steps + 1):
        t = i / steps
        u = 1 - t
        out.append(tuple(u ** 3 * a + 3 * u * u * t * b + 3 * u * t * t * c + t ** 3 * d for a, b, c, d in zip(p0, p1, p2, p3)))
    return out


# The outline on a 24 x 24 grid, the same path the dashboard draws in its header:
# M12 2 4 5 v6 c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11 V5 z
SHIELD = ([(12.0, 2.0), (4.0, 5.0), (4.0, 11.0)] + cubic((4, 11), (4, 16), (7.4, 20.4), (12, 22))
          + cubic((12, 22), (16.6, 20.4), (20, 16), (20, 11)) + [(20.0, 5.0)])
CHECK = [(8.2, 12.4), (11.0, 15.2), (16.0, 9.2)]


def inside(poly, x: float, y: float) -> bool:
    hit = False
    xj, yj = poly[-1]
    for xi, yi in poly:
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            hit = not hit
        xj, yj = xi, yi
    return hit


def on_mark(x: float, y: float) -> bool:
    limit = (MARK_WIDTH / 2) ** 2
    for (ax, ay), (bx, by) in zip(CHECK, CHECK[1:]):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        if (x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2 <= limit:
            return True
    return False


def render(size: int) -> list[list[tuple[int, int, int, int]]]:
    """Rows of (red, green, blue, alpha), smoothed by sampling each pixel several times."""
    samples = 4 if size <= 64 else 3
    scale = size * 0.94 / 20.0                    # the shield is 20 grid units tall
    left, top = size / 2 - 12 * scale, size / 2 - 12 * scale
    rows = []
    for py in range(size):
        row = []
        for px in range(size):
            r = g = b = n = 0
            for sy in range(samples):
                gy = (py + (sy + 0.5) / samples - top) / scale
                if not 2.0 <= gy <= 22.0:
                    continue
                for sx in range(samples):
                    gx = (px + (sx + 0.5) / samples - left) / scale
                    if not 4.0 <= gx <= 20.0 or not inside(SHIELD, gx, gy):
                        continue
                    if on_mark(gx, gy):
                        cr, cg, cb = MARK
                    else:
                        t = (gy - 2.0) / 20.0
                        cr, cg, cb = (TOP[i] + (BOTTOM[i] - TOP[i]) * t for i in range(3))
                    r, g, b, n = r + cr, g + cg, b + cb, n + 1
            row.append((round(r / n), round(g / n), round(b / n), round(255 * n / samples ** 2)) if n else (0, 0, 0, 0))
        rows.append(row)
    return rows


def png(rows) -> bytes:
    size = len(rows)
    raw = b"".join(b"\x00" + bytes(v for pixel in row for v in pixel) for row in rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def dib(rows) -> bytes:
    """The uncompressed form small icon sizes use: a 32-bit bitmap stored bottom row first, then a 1-bit mask."""
    size = len(rows)
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = b"".join(bytes(v for (r, g, b, a) in row for v in (b, g, r, a)) for row in reversed(rows))
    stride = (size + 31) // 32 * 4
    mask = bytearray()
    for row in reversed(rows):
        bits = bytearray(stride)
        for x, pixel in enumerate(row):
            if pixel[3] == 0:
                bits[x // 8] |= 0x80 >> (x % 8)
        mask += bits
    return header + pixels + bytes(mask)


def ico(images: list[tuple[int, bytes]]) -> bytes:
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, data in images:
        out += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return out + b"".join(data for _size, data in images)


def main() -> None:
    pictures = {size: render(size) for size in SIZES}
    images = [(size, png(rows) if size >= 256 else dib(rows)) for size, rows in pictures.items()]
    icon = ROOT / "hostguard" / "assets" / "hostguard.ico"
    icon.parent.mkdir(parents=True, exist_ok=True)
    icon.write_bytes(ico(images))
    picture = ROOT / "docs" / "hostguard.png"
    picture.write_bytes(png(pictures[256]))
    print(f"{icon} ({icon.stat().st_size} bytes, sizes {', '.join(map(str, SIZES))})")
    print(f"{picture} ({picture.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
