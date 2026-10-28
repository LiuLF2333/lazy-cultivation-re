# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")
def dump(a, n, tag=""):
    W("--- %s 0x%08X .. 0x%08X ---" % (tag, a, a+n))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

dump(0x438920, 0x120, "prop container lookup")
dump(0x40e320, 0x80, "40e320")
dump(0x40e850, 0x40, "40e850")
dump(0x42AE80, 0x120, "item record ctor 42AE80")
dump(0x42AD40, 0x140, "row parser tail")
open(r"D:\XiuXian\_analysis\re\s8_prop.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
