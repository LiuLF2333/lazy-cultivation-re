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

dump(0x42A5D0, 0x190, "ItemTable loader tail")
W("### all stores in the whole loader 0x42A25A..0x42A760 ###")
for ins in disasm(pe, 0x42A25A, 0x506):
    if ins[2] == "mov" and "ptr [" in ins[3] and "], e" in ins[3]:
        W("  0x%08X  %s %s" % (ins[0], ins[2], ins[3]))
open(r"D:\XiuXian\_analysis\re\s47_loadertail.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
