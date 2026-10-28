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

dump(0x42A760, 0x720, "row parser full")
open(r"D:\XiuXian\_analysis\re\s21_rowparser_full.txt","w",encoding="utf-8").write(out.getvalue())
dump(0x42DD00, 0x520, "0x42DD00 region")
open(r"D:\XiuXian\_analysis\re\s22_42dd.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
