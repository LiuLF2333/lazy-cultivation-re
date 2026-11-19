# -*- coding: utf-8 -*-
"""Find (1) all callers of 0x48C0F0, (2) what 0x491040 actually does,
(3) every access to [rt+0x50] and [rt+0x599] in the dungeon/timer code."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\battle\s16_report.txt"
pe = PE(EXE)
L = []
def w(s=""): L.append(s)

w("exe: %s" % EXE)

w("\n===== callers of 0x48C0F0 =====")
for va, b, m, o in disasm(pe, 0x401000, 0x243800):
    if m == "call" and o.strip() == "0x48c0f0":
        w("0x%08X  call 0x48C0F0" % va)

w("\n===== 0x491040 (idle nudge) =====")
for va, b, m, o in disasm(pe, 0x491040, 0x120):
    w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

w("\n===== accesses to [x+0x50] / [x+0x599] in 0x48A000-0x492000 =====")
for va, b, m, o in disasm(pe, 0x48A000, 0x8000):
    if "+ 0x50]" in o or "+ 0x599]" in o:
        w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

w("\n===== accesses to [x+0x50] / [x+0x599] in 0x4C5C00-0x4C6700 =====")
for va, b, m, o in disasm(pe, 0x4C5C00, 0xB00):
    if "+ 0x50]" in o or "+ 0x599]" in o:
        w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

open(OUT, "w", encoding="utf-8").write("\n".join(L))
print("wrote %s (%d lines)" % (OUT, len(L)))
