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
def wstr(va, maxb=0x300):
    b = pe.bytes_at(va, maxb); z = b.find(b"\x00\x00")
    if z >= 0: b = b[:z+1]
    if len(b) % 2: b += b"\x00"
    return b.decode("utf-16-le", "replace")

W("'属性异常' @0x689DBC = %r" % wstr(0x689DBC))
W("")
W("### callers of 0x4798B0 ###")
for c in pe.find_calls_to(0x4798B0):
    W("  0x%08X off=0x%06X" % (c, pe.va2off(c)))
    for ins in disasm(pe, c-0x30, 0x30):
        W("      0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
    W("")
dump(0x4798B0, 0x120, "0x4798B0 head")
dump(0x479C60, 0xA0, "属性异常 site 0x479CC5")
open(r"D:\XiuXian\_analysis\re\s54_attrerr.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
