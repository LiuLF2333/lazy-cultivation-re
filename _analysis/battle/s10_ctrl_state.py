# -*- coding: utf-8 -*-
"""Locate the automatic-challenge controller state machine.

The controller keeps its state in the game object:
    0x5A0 state   0x5B4 rounds   0x5B8 timer
    0x596 auto    0x56C target
We find every instruction that touches those fields and the switch that
dispatches on the state value.
"""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

CTRL = {0x5A0: "state", 0x5B4: "rounds", 0x5B8: "timer",
        0x596: "auto", 0x56C: "target"}

pe = PE()
trp, tva, trs = pe.text()
ins = list(disasm(pe, IMAGE_BASE + tva, trs))
print("decoded %d instructions" % len(ins))

prologues = sorted(va for va, b, m, o in ins
                   if b[:3] == b"\x55\x8b\xec" or b[:2] == b"\x6a\xff")

def func_of(va):
    lo, hi = 0, len(prologues) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if prologues[mid] <= va:
            best = prologues[mid]; lo = mid + 1
        else:
            hi = mid - 1
    return best

for off, label in sorted(CTRL.items()):
    needles = ("+ 0x%x]" % off, "+ 0x%X]" % off)
    hits = [(va, m, o) for va, b, m, o in ins
            if any(n in o for n in needles)]
    print("\n=== %s (+0x%X): %d sites ===" % (label, off, len(hits)))
    for va, m, o in hits:
        print("  0x%08X  [fn 0x%08X]  %-8s %s" % (va, func_of(va), m, o))
