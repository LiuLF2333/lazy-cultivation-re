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

dump(0x418540, 0x120, "110 and 132 tooltip cases")
dump(0x476AA0, 0x60, "use_item tooltip call exact")
dump(0x454760, 0x80, "454760 tooltip call exact")
open(r"D:\XiuXian\_analysis\re\s23_110_132.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
