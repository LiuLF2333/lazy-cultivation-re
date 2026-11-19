# -*- coding: utf-8 -*-
"""Locate (a) real writers of [rt+0x4C], (b) the UI click handler that calls
0x48C0F0 (so we can mimic a manual click), (c) the mode dispatch inside
0x48C0F0."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\battle\s15_report.txt"
pe = PE(EXE)
L = []
def w(s=""): L.append(s)

w("exe: %s" % EXE)

# (a) writers of +0x4c
w("\n===== instructions whose DESTINATION is [reg + 0x4c] =====")
n = 0
for va, b, m, o in disasm(pe, 0x401000, 0x243800):
    if "+ 0x4c]" not in o:
        continue
    dst = o.split(",")[0].strip()
    if not dst.endswith("+ 0x4c]"):
        continue
    if m not in ("mov", "movzx", "movsx", "or", "and", "inc", "dec", "add", "sub"):
        continue
    n += 1
    w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))
w("total %d" % n)

# (b) UI click handler
for name, lo, hi in [
    ("caller 0x48C0F0 @0x4BD7F6", 0x4BD770, 0x4BD830),
    ("UI handlers 0x4C8950-0x4C89F0", 0x4C8950, 0x4C89F0),
    ("UI handlers 0x4C8A60-0x4C8C60", 0x4C8A60, 0x4C8C60),
]:
    w("\n===== %s =====" % name)
    for va, b, m, o in disasm(pe, lo, hi - lo):
        w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

# (c) 0x48C0F0 mode dispatch
w("\n===== 0x48C0F0 head + mode dispatch =====")
for va, b, m, o in disasm(pe, 0x48C0F0, 0x120):
    w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))
w("\n----- every cmp [x+0x4c] inside 0x48C0F0..0x48CC00 -----")
for va, b, m, o in disasm(pe, 0x48C0F0, 0xB10):
    if "+ 0x4c]" in o and m == "cmp":
        w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

open(OUT, "w", encoding="utf-8").write("\n".join(L))
print("wrote %s (%d lines)" % (OUT, len(L)))
