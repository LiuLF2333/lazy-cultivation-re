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

dump(0x40e180, 0x2C0, "container helpers")
W("=== raw bytes file 0xD700..0xD760 ===")
o = pe.va2off(0x40e300)
W(pe.raw[o:o+0x60].hex())

W("")
W("=== 0x60eebd / 0x60ec24 / 0x60ed6c / 0x60edb3 heads ===")
for v in (0x60eebd, 0x60ec24, 0x60ed6c, 0x60edb3, 0x41baa0):
    W("--- 0x%08X ---" % v)
    for ins in disasm(pe, v, 0x50):
        W("0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
    W("")

open(r"D:\XiuXian\_analysis\re\s9_cont.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
