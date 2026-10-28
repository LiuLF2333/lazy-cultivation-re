# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")
def dump(a, n, tag=""):
    W("--- %s 0x%08X .. 0x%08X ---" % (tag, a, a+n))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

dump(0x4D3B80, 0xC0, "switch head at 0x4D3BF0")
W("=== table at 0x4D416C, 64 entries ===")
for i in range(70):
    v = pe.u32(0x4D416C + i*4)
    W("  entry[%2d] idx_type1_if_base100=%3d -> 0x%08X" % (i, 100+i, v if v else 0))
W("")
dump(0x4D3C60, 0x1C0, "handlers 0x4D3C65 .. ")
open(r"D:\XiuXian\_analysis\re\s37_switch.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
