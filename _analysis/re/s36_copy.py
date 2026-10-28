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

dump(0x40AE80, 0x1A0, "copy/src->item 0x40AE80..")
dump(0x42DEC0, 0x260, "0x42DEC0 (writes +0x290/+0x294)")
dump(0x42DD00, 0x1C0, "0x42DD00 head")
open(r"D:\XiuXian\_analysis\re\s36_copy.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
