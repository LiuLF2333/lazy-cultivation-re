# -*- coding: utf-8 -*-
"""Dump the dungeon aftermath/result region with clean boundaries and list
every control-flow edge that lands on 0x48FE4C (the auto-retry hook site)."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, IMAGE_BASE

pe = PE()
ins = list(disasm(pe, 0x48FA80, 0x3E0))

print("=== code 0x48FA80..0x48FE60 ===")
for va, b, m, o in ins:
    mark = ""
    if va == 0x48FE4C:
        mark = "   <== HOOK SITE (vanilla: jmp 0x48FF0B)"
    print("0x%08X  %-22s %-9s %s%s" % (va, b.hex(), m, o, mark))

print("\n=== jumps into 0x48FE4C ===")
for va, b, m, o in ins:
    if m.startswith("j") and ("0x48fe4c" in o or "0x48FE4C" in o):
        print("  0x%08X  %-22s %-9s %s" % (va, b.hex(), m, o))

print("\n=== writes to [obj+0x44] and [obj+0x4C] in 0x48F000..0x491100 ===")
allins = list(disasm(pe, 0x48F000, 0x2100))
for va, b, m, o in allins:
    for f in ("+ 0x44]", "+ 0x4c]"):
        if f in o and m in ("mov", "movzx", "cmp"):
            print("  0x%08X  %-9s %s" % (va, m, o))
            break
