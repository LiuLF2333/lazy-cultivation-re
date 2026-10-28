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

dump(0x40AE80, 0x1C0, "prop accessor 0x40AE..")
dump(0x426800, 0x80, "426800")
dump(0x432030, 0x80, "432030")
dump(0x476740, 0x80, "use_item prologue")
open(r"D:\XiuXian\_analysis\re\s34_accessor.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
