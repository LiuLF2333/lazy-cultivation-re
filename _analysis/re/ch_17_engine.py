# -*- coding: utf-8 -*-
"""Dump the real selection engine's core functions."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_17_engine.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE()

def dump(va, n, label=""):
    P("=" * 96)
    P("0x%08X (%s) off=0x%X" % (va, label, pe.va2off(va)))
    P("=" * 96)
    for ins in disasm(pe, va, n):
        P("   " + fmt(ins))
    P("")

for va, n, lb in [
    (0x408730, 0x40, "is-toggle-target?"),
    (0x408760, 0x30, "clear/reset"),
    (0x408780, 0x40, "begin/end?"),
    (0x4087A0, 0x30, "set"),
    (0x4087C0, 0x30, "get"),
    (0x4087E0, 0x60, "GetCount?"),
    (0x408830, 0x60, "GetNext?"),
    (0x409520, 0x140, "the final consumer"),
    (0x405A10, 0x20, ""),
    (0x405A20, 0x40, ""),
    (0x4CFE86, 0x80, "called on gameobj"),
    (0x408350, 0x180, "loop region containing the chooser"),
    (0x408500, 0x80, "after loop: apply the choice"),
]:
    dump(va, n, lb)
OUT.close()
print("ok")
