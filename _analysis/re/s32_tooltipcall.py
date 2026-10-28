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

dump(0x476A60, 0xB0, "use_item tooltip call exact")
dump(0x4183B0, 0xD0, "tooltip builder prologue")
dump(0x439680, 0x40, "439680 getter")
dump(0x4396f0, 0x40, "4396f0 getter-str")
open(r"D:\XiuXian\_analysis\re\s32_tooltipcall.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
