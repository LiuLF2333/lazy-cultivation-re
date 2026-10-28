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

W("### candidate dispatcher 0x41A340 region ###")
dump(0x41A330, 0xE0, "0x41A330")
W("### table 0x41B528 ###")
for i in range(70):
    v = pe.u32(0x41B528 + i*4)
    W("  [%2d] 0x%08X" % (i, v))
W("")
dump(0x41B528, 0x40, "table bytes")
open(r"D:\XiuXian\_analysis\re\s39_cand.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
