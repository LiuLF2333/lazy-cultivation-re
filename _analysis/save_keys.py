# -*- coding: utf-8 -*-
"""Locate the character save serialization keys and the ablePt field usage."""
import struct, io
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\save_keys.txt"
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


# The save keys we saw: ablePt, savvy1..5, ableKey, ableEr, ableLastLv
# find their VAs and search .text for immediate references (push imm32)
KEYS = ["ablePt", "ableLastLv", "ableKey", "ableEr", "savvy1", "savvyMax",
        "jiedanLv", "zhuan", "ageCount"]

lines = ["Save-field string locations and code references", "=" * 70]
for k in KEYS:
    # wide string search
    w = k.encode("utf-16-le")
    offs = []
    st = 0
    while True:
        i = raw.find(w, st)
        if i < 0:
            break
        offs.append(i)
        st = i + 1
        if len(offs) > 6:
            break
    lines.append("%-12s wide offsets: %s" % (k, [hex(o) for o in offs]))
    # find push imm32 of the VA
    tn, tva, tvs, trp, trs = [s for s in secs if s[0] == ".text"][0]
    text = raw[trp:trp + trs]
    for o in offs[:3]:
        # compute VA of this string
        sva = None
        for nm, va, vs, rp, rs in secs:
            if rp <= o < rp + rs:
                sva = IB + va + (o - rp)
        if sva is None:
            continue
        imm = struct.pack("<I", sva)
        refs = []
        st2 = 0
        while True:
            i2 = text.find(imm, st2)
            if i2 < 0:
                break
            refs.append(hex(IB + tva + i2))
            st2 = i2 + 1
            if len(refs) > 8:
                break
        lines.append("              VA 0x%X referenced at: %s" % (sva, refs))

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("\n".join(lines))
