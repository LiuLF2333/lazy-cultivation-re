# -*- coding: utf-8 -*-
"""Dump the attribute-apply block in the item-use function (0x476FA0..0x477200)."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\apply_block.txt"
f = io.StringIO()

insns = list(disasm(pe, 0x476F80, 0x2E0))
for ins in insns:
    f.write(fmt(ins) + "\n")

f.write("\n### string pushes\n")
for va, b, m, o in insns:
    if m == "push" and o.startswith("0x"):
        v = int(o, 16)
        if 0x600000 < v < 0x6D0000:
            f.write("  0x%08X push %s -> %r\n" % (va, o, pe.wide(v, 100)))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
