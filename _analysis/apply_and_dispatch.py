# -*- coding: utf-8 -*-
"""1) Disassemble 0x43B160..0x43B2C0 (candidate attr-apply for type1=132).
2) Look at how 0x473490 (the real use executor) dispatches."""
import io, re, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\apply_and_dispatch.txt"
f = io.StringIO()

f.write("=" * 78 + "\n### candidate attribute-apply 0x43B180..0x43B2D0\n" + "=" * 78 + "\n")
for ins in disasm(pe, 0x43B160, 0x180):
    f.write(fmt(ins) + "\n")

f.write("\n\n" + "=" * 78 + "\n### 0x473490 head: control flow / jump tables\n" + "=" * 78 + "\n")
insns = list(disasm(pe, 0x473490, 0x1600))
for ins in insns[:140]:
    f.write(fmt(ins) + "\n")

f.write("\n\n### jump-table indirect jumps inside 0x473490..0x474A90\n")
for va, b, m, o in insns:
    if m == "jmp" and "[" in o:
        f.write("  0x%08X  jmp %s\n" % (va, o))

f.write("\n\n### cmp/sub with imm in 99..140 inside 0x473490 region\n")
for va, b, m, o in insns:
    if m in ("cmp", "sub") and re.search(r", 0x[0-9a-f]{2,3}$", o):
        imm = int(o.rsplit(", ", 1)[1], 16)
        if 99 <= imm <= 140:
            f.write("  0x%08X  %s %s\n" % (va, m, o))

f.write("\n\n### all direct call targets inside 0x473490 region\n")
seen = []
for va, b, m, o in insns:
    if m == "call" and o.startswith("0x"):
        seen.append((va, o))
for va, o in seen:
    f.write("  0x%08X  call %s\n" % (va, o))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok insns=%d" % len(insns))
