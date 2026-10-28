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

W("### strings ###")
for va in (0x6812B0, 0x6812FC, 0x6814C4, 0x6815C4, 0x6816FC, 0x681734, 0x68176C):
    W("  0x%08X = %r" % (va, pe.cstr(va)))
W("")
dump(0x4184D0, 0x60, "handler idx7 = type1 107")
dump(0x4185B0, 0x80, "handler idx10 = type1 110 and idx12")
dump(0x4183D4, 0x40, "dispatch re-verify")
open(r"D:\XiuXian\_analysis\re\s43_handlers.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
