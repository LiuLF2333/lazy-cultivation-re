# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

W("=== search backwards for prologue before 0x418400 ===")
for ins in disasm(pe, 0x418340, 0xC0):
    W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))

W("")
W("=== 110 branch region: 0x4185B0..0x418650 ===")
for ins in disasm(pe, 0x4185B0, 0xA0):
    W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))

W("")
W("=== strings ===")
for va in (0x6814C4, 0x6815C4, 0x681380, 0x681400, 0x68148C, 0x681520, 0x6812b0, 0x6812cc, 0x6812f0, 0x681328, 0x681348):
    W("  0x%08X : %r" % (va, pe.wide(va)))

open(r"D:\XiuXian\_analysis\re\s1b_prologue.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
