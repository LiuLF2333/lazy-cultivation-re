# -*- coding: utf-8 -*-
"""Inspect the second type1 dispatch table at site 0x60722F / table 0x607DE8."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\table_607.txt"
f = io.StringIO()

f.write("### context around site 0x60722F (the jmp [reg*4+0x607DE8])\n")
for ins in disasm(pe, 0x6071E0, 0x90):
    f.write(fmt(ins) + "\n")

f.write("\n### raw dwords of table 0x607DE8 (40 entries)\n")
for k in range(40):
    f.write("  +0x%02X  [%2d] 0x%08X\n" % (k * 4, k, pe.u32(0x607DE8 + k * 4) or 0))

f.write("\n### entry blocks: disasm first 0x30 bytes of each distinct target\n")
seen = []
for k in range(32):
    v = pe.u32(0x607DE8 + k * 4)
    if v and v not in seen:
        seen.append(v)
for v in sorted(seen):
    f.write("\n--- target 0x%08X\n" % v)
    for ins in disasm(pe, v, 0x30):
        f.write("    " + fmt(ins) + "\n")

# What region is 0x607000?
trp, tva, trs = pe.text()
f.write("\n### .text covers VA 0x%X .. 0x%X\n" % (IMAGE_BASE + tva, IMAGE_BASE + tva + trs))
f.write("    0x60722F inside .text: %s\n" % (IMAGE_BASE + tva <= 0x60722F < IMAGE_BASE + tva + trs))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
