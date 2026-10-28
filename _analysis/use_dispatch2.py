# -*- coding: utf-8 -*-
"""Search the item-use region for the type1 dispatch: look for a load of the
type1 field (offset 0 of the item def ptr) followed by a range comparison or
a chain against 100..132."""
import io, re, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt, _md

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\use_dispatch2.txt"
f = io.StringIO()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]

# Build a decoded window over the item-use region and look for type1 patterns.
START, END = 0x476740, 0x478000
insns = list(disasm(pe, START, END - START))
f.write("### decoded %d insns in 0x%X..0x%X\n" % (len(insns), START, END))

f.write("\n### cmp/sub with imm in 90..140\n")
for va, b, m, o in insns:
    if m in ("cmp", "sub", "add") and re.search(r", 0x[0-9a-f]{2,3}$", o):
        imm = int(o.rsplit(", ", 1)[1], 16)
        if 90 <= imm <= 140:
            f.write("  0x%08X  %s %s\n" % (va, m, o))

f.write("\n### indirect jumps (jump tables)\n")
for va, b, m, o in insns:
    if m == "jmp" and "[" in o:
        f.write("  0x%08X  jmp %s\n" % (va, o))

f.write("\n### call 0x426240 sites with context\n")
for va, b, m, o in insns:
    if m == "call" and o == "0x426240":
        f.write("\n--- 0x%08X\n" % va)
        k = [i for i, x in enumerate(insns) if x[0] == va][0]
        for j in range(max(0, k - 14), min(len(insns), k + 6)):
            a2, b2, m2, o2 = insns[j]
            mark = ">>" if a2 == va else "  "
            f.write("  %s 0x%08X %-12s %s\n" % (mark, a2, m2, o2))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
