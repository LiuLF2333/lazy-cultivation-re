# -*- coding: utf-8 -*-
import sys, io, os
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

W("=== tooltip builder VA 0x418400, first 0x180 bytes ===")
for ins in disasm(pe, 0x418400, 0x180):
    W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))

W("")
W("=== jump table at 0x418CA8, 40 entries ===")
for i in range(40):
    v = pe.u32(0x418CA8 + i*4)
    W("  idx type1=%d -> 0x%08X" % (100+i, v))

open(r"D:\XiuXian\_analysis\re\s1_tooltip.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
