# -*- coding: utf-8 -*-
"""Disassemble the region around the 'six base attributes increased' messages
(0x415B8C / 0x415BAE / 0x415BC7) to recover the base-attribute apply helper."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\six_attr.txt"
f = io.StringIO()

f.write("### disasm 0x415A00 .. 0x416120\n")
insns = list(disasm(pe, 0x415A00, 0x720))
for ins in insns:
    f.write(fmt(ins) + "\n")

f.write("\n\n### string pushes in range\n")
for va, b, m, o in insns:
    if m == "push" and o.startswith("0x"):
        v = int(o, 16)
        if 0x600000 < v < 0x6D0000:
            f.write("  0x%08X push %s -> %r\n" % (va, o, pe.wide(v, 100)))

f.write("\n\n### calls in range\n")
for va, b, m, o in insns:
    if m == "call" and o.startswith("0x"):
        f.write("  0x%08X call %s\n" % (va, o))

# searches for repeated pattern of add-to-6-fields
f.write("\n\n### any instruction with disp 0x1a4/0x1a8/0x1b0 (possible attr array)\n")
for va, b, m, o in insns:
    if any(hex(d) in o for d in (0x1A0, 0x1A4, 0x1A8, 0x1AC, 0x1B0, 0x1B4)):
        f.write("  0x%08X  %s %s\n" % (va, m, o))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
