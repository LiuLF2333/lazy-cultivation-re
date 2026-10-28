# -*- coding: utf-8 -*-
"""Examine the item-effect executor region 0x43A000-0x43B400."""
import io, re, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, _md, IMAGE_BASE

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\effect_43a.txt"
f = io.StringIO()

f.write("### disasm 0x43AC00 .. 0x43B320\n")
insns = list(disasm(pe, 0x43AC00, 0x720))
for ins in insns:
    f.write(fmt(ins) + "\n")

f.write("\n\n### cmp/sub immediates in 100..135 within this region\n")
for va, b, m, o in insns:
    if m in ("cmp", "sub") and re.search(r", 0x[0-9a-f]{2,3}$", o):
        imm = int(o.rsplit(", ", 1)[1], 16)
        if 100 <= imm <= 135:
            f.write("  0x%08X  %s %s\n" % (va, m, o))

f.write("\n\n### calls out of this region\n")
for va, b, m, o in insns:
    if m == "call" and o.startswith("0x"):
        f.write("  0x%08X  call %s\n" % (va, o))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
