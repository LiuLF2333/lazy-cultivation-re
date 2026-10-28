# -*- coding: utf-8 -*-
"""Find the real 'use item' action: locate the random-attribute roll and the
attribute-add routine so a patch target can be named precisely."""
import struct, io
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\use_action.txt"
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
tn, tva, tvs, trp, trs = [s for s in secs if s[0] == ".text"][0]
md = Cs(CS_ARCH_X86, CS_MODE_32)

f = io.StringIO()

# The desc-builder function 0x418400 has no direct callers, so it is invoked
# indirectly (virtual method / function pointer). Find its VA as a data dword
# anywhere in the image -> that gives the vtable slot.
def find_dword(val):
    b = struct.pack("<I", val)
    out = []
    st = 0
    while True:
        i = raw.find(b, st)
        if i < 0:
            break
        out.append(i)
        st = i + 1
    return out

f.write("### data references to 0x418400 (desc builder) as a dword\n")
for o in find_dword(0x418400):
    sva = None
    for nm, va, vs, rp, rs in secs:
        if rp <= o < rp + rs:
            sva = IB + va + (o - rp)
    f.write("  file 0x%X  VA 0x%X\n" % (o, sva if sva else -1))

f.write("\n### data references to 0x20B000-ish (validation) as a dword\n")
for target in (0x20B2A0, 0x20B2B0, 0x20B000, 0x20B290):
    refs = find_dword(target)
    f.write("  0x%X -> %d refs %s\n" % (target, len(refs), [hex(r) for r in refs[:6]]))

# Identify .rdata vtables region: dump dwords near 0x60A000-0x610000 for
# pointers into the desc-builder function range
f.write("\n### scan for vtables containing pointers into 0x418xxx\n")
a, b = 0x60A000, 0x614000
for nm, va, vs, rp, rs in secs:
    if rp <= (a - IB) < rp + rs or True:
        pass
# map VA->file for the range using .rdata
def va2off(va):
    rva = va - IB
    for nm, sva, vs, rp, rs in secs:
        if sva <= rva < sva + max(vs, rs):
            return rp + (rva - sva)
    return None

o = va2off(a)
cnt = 0
for k in range(0, (b - a) // 4):
    v = struct.unpack_from("<I", raw, o + k * 4)[0]
    if 0x418000 <= v <= 0x419000:
        f.write("  0x%X: 0x%X\n" % (a + k * 4, v))
        cnt += 1
        if cnt > 40:
            break

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
