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

dump(0x60EEC0, 0x180, "0x60eebd tokenizer + 0x60ec24")
dump(0x439E80, 0xA0, "predicate using +0x290/+0x294")
dump(0x43ADA0, 0x140, "43ADA0 copy w/ 0x278/0x294")
open(r"D:\XiuXian\_analysis\re\s48_tok.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
