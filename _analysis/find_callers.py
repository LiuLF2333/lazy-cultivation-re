# -*- coding: utf-8 -*-
"""Find callers of the item-desc builder and locate the real 'use item' path."""
import struct, io
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\callers.txt"
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
text = raw[trp:trp + trs]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

lines = []


def find_calls(target_va):
    """Linear sweep for `call rel32` resolving to target_va."""
    res = []
    rel = target_va - (tva + IB)
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            off = struct.unpack_from("<i", text, i + 1)[0]
            # call site VA = IB + tva + i ; target = site+5+off
            site = tva + i
            if site + 5 + off == target_va - IB:
                res.append(IB + site)
    return res


# 0x418400 is the dispatcher entry (the function containing the type1 switch)
for target in [0x418400, 0x4183F0, 0x4183E0, 0x4183D0]:
    c = find_calls(target)
    if c:
        lines.append("callers of 0x%X: %s" % (target, [hex(x) for x in c[:20]]))

# Broader: find the function start. Scan backward from 0x418400 for int3 padding
start = 0x418400 - IB
k = start
while k > 0 and text[k - 1] in (0xCC, 0x90):
    k -= 1
lines.append("function containing 0x418400 starts at VA 0x%X" % (IB + k))

# search calls to that function start
c = find_calls(IB + k)
lines.append("callers of 0x%X: %s" % (IB + k, [hex(x) for x in c[:30]]))

lines.append("")
lines.append("Also scan for calls to 0x40E4F0 (string append helper):")
c2 = find_calls(0x40E4F0)
lines.append("  count=%d  first=%s" % (len(c2), [hex(x) for x in c2[:15]]))

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("\n".join(lines))
