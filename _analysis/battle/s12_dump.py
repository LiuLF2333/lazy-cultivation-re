# -*- coding: utf-8 -*-
"""Full picture of the dungeon auto-challenge controller.

Writes a report file so nothing is lost to console truncation.
"""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, IMAGE_BASE

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\XiuXian\懒人修仙传.exe"
OUT = sys.argv[2] if len(sys.argv) > 2 else r"D:\XiuXian\_analysis\battle\s12_report.txt"

pe = PE(EXE)
lines = []


def w(s=""):
    lines.append(s)


w("exe: %s" % EXE)
w("sections:")
for s in pe.sections:
    w("  %-8s VA 0x%08X vsize 0x%-6X rawptr 0x%-6X rawsize 0x%-6X"
      % (s["name"], IMAGE_BASE + s["va"], s["vsize"], s["rawptr"], s["rawsize"]))

for name, lo, hi in [
    ("result dispatch 0x48FB00", 0x48FB00, 0x48FD80),
    ("defeat exit 0x48FD80", 0x48FD80, 0x48FF28),
    ("state dispatch 0x490C20", 0x490C20, 0x490E40),
    ("state 4 restart 0x490E40", 0x490E40, 0x490E60),
    ("OnTimer dungeon block", 0x4C5F30, 0x4C6060),
]:
    w("\n===== %s =====" % name)
    for va, b, m, o in disasm(pe, lo, hi - lo):
        w("0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("wrote %s (%d lines)" % (OUT, len(lines)))
