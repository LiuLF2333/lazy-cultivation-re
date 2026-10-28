# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

W("### byte index table 0x41B674 (type1-1 -> handler idx) ###")
b = pe.bytes_at(0x41B674, 256)
for i in range(0, 256, 8):
    W("  [%3d..] %s" % (i, " ".join("%3d" % x for x in b[i:i+8])))
W("")

W("### type1 -> handler VA mapping ###")
for t1 in (0, 100, 105, 106, 107, 108, 110, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 126, 127, 128, 129, 130, 131, 132, 200, 201, 202, 203, 204, 300, 302, 303):
    i = t1 - 1
    if 0 <= i < 256:
        hi = b[i]
        hv = pe.u32(0x41B528 + hi*4) if hi < 70 else 0
        W("  type1=%3d -> idx(byte[0x41B674+%d])=%3d -> handler 0x%08X" % (t1, i, hi, hv))
W("")

W("### callers of 0x41A360 ###")
for c in pe.find_calls_to(0x41A360):
    W("  site 0x%08X off=0x%06X" % (c, pe.va2off(c)))
    for ins in disasm(pe, c-0x30, 0x30):
        W("     0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
    W("")
W("### callers of 0x41A3C9 (via jmp) - just in case ###")
open(r"D:\XiuXian\_analysis\re\s46_map.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
