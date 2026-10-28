# -*- coding: utf-8 -*-
"""Disassemble the real item-use handler 0x473490 and locate the type1 dispatch,
especially the 110 (random base attribute) and 132 (targeted attribute) branches."""
import io, re, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\use_handler_473490.txt"
f = io.StringIO()

START = 0x473490
N = 0x1400
insns = list(disasm(pe, START, N))
f.write("# item-use handler 0x%X, %d instructions decoded\n" % (START, len(insns)))
f.write("#" * 78 + "\n")
for ins in insns:
    f.write(fmt(ins) + "\n")

# collect immediate comparisons to identify the type1 dispatch
f.write("\n\n### comparisons with immediates (candidate type1 dispatch)\n")
for va, b, m, o in insns:
    if m in ("cmp", "sub") and re.search(r", 0x[0-9a-f]+$", o):
        try:
            imm = int(o.split(", ")[1], 16)
        except Exception:
            continue
        if 90 <= imm <= 140:
            f.write("  0x%08X  %s %s\n" % (va, m, o))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
