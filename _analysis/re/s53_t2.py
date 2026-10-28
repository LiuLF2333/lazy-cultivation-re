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

dump(0x419880, 0x140, "0x419880 region (2nd table 0x419A58)")
W("table 0x419A58:")
for i in range(28):
    W("  [%2d] 0x%08X" % (i, pe.u32(0x419A58 + i*4)))
W("")
dump(0x4190D8, 0xA0, "byte table 0x4191D8 + jmp 0x419190")
for i in range(0, 104, 8):
    W("  0x4191D8[%2d..] %s" % (i, " ".join("%3d" % x for x in pe.bytes_at(0x4191D8+i, 8))))
W("")
W("table 0x4191B4 (small):")
for i in range(28):
    W("  [%2d] 0x%08X" % (i, pe.u32(0x4191B4 + i*4)))
W("")
dump(0x48E800, 0x60, "0x48e800")
open(r"D:\XiuXian\_analysis\re\s53_t2.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
