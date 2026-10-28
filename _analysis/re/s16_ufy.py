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

dump(0x412300, 0x240, "youfuyong handler A")
dump(0x412540, 0x200, "youfuyong handler B")
dump(0x417dc0, 0x140, "无效属性 user")
for ins in disasm(pe, 0x417e00, 0xB0):
    W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))

open(r"D:\XiuXian\_analysis\re\s16_ufy.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
