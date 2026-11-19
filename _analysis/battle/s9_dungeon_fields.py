# -*- coding: utf-8 -*-
"""Map the dungeon auto-challenge state machine.

Locates every instruction touching the controller fields and every jump that
enters the 0x48FE4C failure exit, so we can tell whether one hook covers all
failure paths.
"""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

FIELDS = {
    0x5A0: "state",
    0x5B4: "rounds",
    0x5B8: "timer",
    0x596: "auto",
    0x56C: "target",
    0x570: "ctrl?",
    0x40:  "phase",
    0x44:  "res",
}

pe = PE()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]

# Decode the whole .text once so we can look for memory operands.
ins = list(disasm(pe, IMAGE_BASE + tva, trs))

print("total decoded instructions: %d" % len(ins))

# Function boundaries: prologues `55 8B EC` (push ebp; mov ebp,esp) and `6A FF` SEH.
prologue = set()
for va, b, m, o in ins:
    if b[:3] == b"\x55\x8b\xec" or b[:2] == b"\x6a\xff":
        prologue.add(va)

def func_of(va):
    best = None
    for p in prologue:
        if p <= va and (best is None or p > best):
            best = p
    return best

print("\n=== instruction sites referencing controller fields ===")
for name_off, label in sorted(FIELDS.items()):
    hits = []
    for va, b, m, o in ins:
        if ("+ 0x%x]" % name_off) in o or ("+ 0x%X]" % name_off) in o:
            hits.append((va, m, o))
    print("\n-- %s (+0x%X): %d sites" % (label, name_off, len(hits)))
    for va, m, o in hits:
        print("   0x%08X  %-10s %s" % (va, m, o))
