# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

W("=== strings 0x68a9a0..0x68a9f0 wide ===")
for va in range(0x68a9a0, 0x68a9f0, 4):
    w = pe.wide(va)
    c = pe.cstr(va)
    if w and len(w) > 0 and all(0x20 <= ord(ch) < 0x3000 for ch in w):
        W("  0x%08X wide=%r" % (va, w))
    if c and len(c) > 1 and all(0x20 <= ord(ch) < 0x3000 for ch in c):
        W("  0x%08X cstr=%r" % (va, c))

W("")
W("=== 0x442dc0 / 0x442300 / 0x442690 heads ===")
for va in (0x442dc0, 0x442300, 0x442690):
    W("--- 0x%08X ---" % va)
    for ins in disasm(pe, va, 0x40):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

W("=== function containing 0x4847A0: find prologue ===")
for ins in disasm(pe, 0x484760, 0x60):
    W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))

open(r"D:\XiuXian\_analysis\re\s1d_strings.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
