# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\XiuXian\懒人修仙传.exe"
OUT = sys.argv[2] if len(sys.argv) > 2 else r"D:\XiuXian\_analysis\battle\s13_report.txt"
pe = PE(EXE)
L = []
def w(s=""): L.append(s)

w("exe: %s" % EXE)
for name, lo, hi in [
    ("caller of 0x490C20  (0x4C6340-0x4C6440)", 0x4C6340, 0x4C6440),
    ("mode writers 0x48E?? ", 0x48ED40, 0x48EDC0),
    ("mode writer 0x48EF09", 0x48EEC0, 0x48EF40),
    ("mode writer 0x48F1C5", 0x48F180, 0x48F210),
    ("dungeon enter 0x48C4A9", 0x48C470, 0x48C4E0),
]:
    w("\n===== %s =====" % name)
    for va, b, m, o in disasm(pe, lo, hi - lo):
        w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

open(OUT, "w", encoding="utf-8").write("\n".join(L))
print("wrote %s (%d lines)" % (OUT, len(L)))
