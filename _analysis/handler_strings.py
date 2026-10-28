# -*- coding: utf-8 -*-
"""Decode UTF-16LE strings at the VAs referenced by type1 handlers."""
import struct, io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\handler_strings.txt"
raw = open(EXE, "rb").read()
IB = 0x400000

pe = struct.unpack_from("<I", raw, 0x3c)[0]
nsec = struct.unpack_from("<H", raw, pe + 6)[0]
opt = pe + 24
sec = opt + struct.unpack_from("<H", raw, pe + 20)[0]
secs = []
for i in range(nsec):
    o = sec + i * 40
    nm = raw[o:o + 8].rstrip(b"\x00").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", raw, o + 8)
    secs.append((nm, va, vs, rp, rs))


def va2off(va):
    rva = va - IB
    for nm, sva, vs, rp, rs in secs:
        if sva <= rva < sva + max(vs, rs):
            return rp + (rva - sva)
    return None


def wide_at(va, maxlen=400):
    o = va2off(va)
    if o is None:
        return None
    out = []
    i = o
    while i + 1 < len(raw) and len(out) < maxlen:
        cp = raw[i] | (raw[i + 1] << 8)
        if cp == 0:
            break
        out.append(cp)
        i += 2
    if not out:
        return None
    return bytes(b for cp in out for b in (cp & 0xFF, cp >> 8)).decode("utf-16-le", errors="replace")


CONSTS = [
    (0x6812B0, "type1=100"), (0x6812CC, "type1=101"), (0x6812F0, "type1=102"),
    (0x681328, "type1=105"), (0x681348, "type1=106 (fmt)"), (0x6814C4, "type1=110"),
    (0x6815C4, "type1=132"), (0x681628, "type1=112"), (0x6813D4, "type1=113"),
    (0x6814F4, "type1=114"),
]

lines = ["UTF-16LE strings referenced by type1 handlers", "=" * 70]
for c, who in CONSTS:
    s = wide_at(c)
    lines.append("%-18s 0x%X: %r" % (who, c, s))

lines.append("")
lines.append("Full UTF-16LE dump, VA 0x682800 - 0x682C00 (description templates)")
lines.append("=" * 70)
a, b = 0x682800, 0x682C00
oa, ob = va2off(a), va2off(b)
i = oa
while i < ob:
    j = i
    ch = []
    while j + 1 < ob:
        cp = raw[j] | (raw[j + 1] << 8)
        if cp == 0:
            break
        ch.append(cp)
        j += 2
    if len(ch) >= 2:
        s = bytes(x for cp in ch for x in (cp & 0xFF, cp >> 8)).decode("utf-16-le", errors="replace")
        lines.append("  0x%X  %s" % (a + (i - oa), s))
        i = j + 2
    else:
        i += 2

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("ok")
