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

dump(0x479B00, 0x320, "around 0x479cc5 (属性异常)")

W("=== strings near 0x689db0 ===")
for va in range(0x689d80, 0x689e20, 2):
    w = pe.wide(va)
    if w and all(ord(c) >= 0x20 for c in w):
        W("  0x%08X %r" % (va, w))

open(r"D:\XiuXian\_analysis\re\s20_attrerr.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
