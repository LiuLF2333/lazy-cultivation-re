# -*- coding: utf-8 -*-
"""Examine the six-base-attribute UI region 0x4AF800..0x4AFC80."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\allociu.txt"
f = io.StringIO()
insns = list(disasm(pe, 0x4AF7C0, 0x4C0))
for ins in insns:
    f.write(fmt(ins) + "\n")
f.write("\n### push imm32 sites (string refs)\n")
for va, b, m, o in insns:
    if m == "push" and o.startswith("0x") and int(o, 16) > 0x600000:
        f.write("  0x%08X push %s -> %r\n" % (va, o, pe.wide(int(o, 16), 60)))
f.write("\n### direct calls\n")
for va, b, m, o in insns:
    if m == "call" and o.startswith("0x"):
        f.write("  0x%08X call %s\n" % (va, o))
open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
