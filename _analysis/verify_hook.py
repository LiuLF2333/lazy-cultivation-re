# -*- coding: utf-8 -*-
"""Verify the hook site contract: what follows 0x476FC7, and that the callee is
cdecl (caller cleans the pushed arg)."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
print("--- 0x476FB4 .. 0x476FF6 (hook context) ---")
for va, b, m, o in disasm(pe, 0x476FB4, 0x476FF6 - 0x476FB4):
    mark = "  <== HOOK" if va == 0x476FC7 else ""
    print("  0x%08X  %-22s %s%s" % (va, b.hex(), fmt((va, b, m, o)).strip(), mark))
print("--- callee 0x41A120 head (ret form) ---")
for va, b, m, o in disasm(pe, 0x41A120, 0x60):
    print("  0x%08X  %-22s %s %s" % (va, b.hex(), m, o))
    if m == "ret":
        break
