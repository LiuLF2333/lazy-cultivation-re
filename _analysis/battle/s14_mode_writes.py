# -*- coding: utf-8 -*-
"""Every instruction in .text that writes the mode field [rt+0x4C], plus the
0x48C6FD branch target inside the dungeon entry routine."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\battle\s14_report.txt"
pe = PE(EXE)
L = []
def w(s=""): L.append(s)

w("exe: %s" % EXE)
w("\n===== writes to [x + 0x4c] =====")
n = 0
for va, b, m, o in disasm(pe, 0x401000, 0x243800):
    if "+ 0x4c]" not in o:
        continue
    if not (m.startswith("mov ") and not m.startswith("movzx")):
        continue
    # destination must be first operand
    dst = o.split(",")[0]
    if "+ 0x4c]" not in dst:
        continue
    n += 1
    w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))
w("total %d" % n)

w("\n===== 0x48C6E0..0x48C760 =====")
for va, b, m, o in disasm(pe, 0x48C6E0, 0x90):
    w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

open(OUT, "w", encoding="utf-8").write("\n".join(L))
print("wrote %s (%d lines)" % (OUT, len(L)))
