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

dump(0x4C9200, 0x220, "handler 0x4C9220 (msg 0x405) + neighbours")
dump(0x4C91D0, 0x40, "handler 0x4C91F0 head")
dump(0x461730, 0x120, "handler 0x461750 (msg 0x405)")
W("=== global 0x6c8870, 0x6c886c, 0x6c86e8 ===")
for g in (0x6C8870, 0x6C886C, 0x6C86E8, 0x6C8878):
    W("  [0x%08X] = 0x%08X" % (g, pe.u32(g)))
open(r"D:\XiuXian\_analysis\re\s28_handlers.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
