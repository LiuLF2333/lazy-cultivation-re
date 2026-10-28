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

# locate enclosing function of 0x4123C5
def find_func(va, back=0x1000):
    for x in range(va-4, max(0x401000, va-back), -1):
        if pe.bytes_at(x, 3) == b"\x55\x8b\xec":
            if pe.bytes_at(x-1,1) in (b"\xcc", b"\xc3"):
                return x
    return None
for va in (0x4123C5, 0x4125B5, 0x4183B0, 0x476AEB, 0x4185C5):
    W("func containing 0x%08X = 0x%08X" % (va, find_func(va) or 0))
W("")
dump(0x4183B0, 0x70, "tooltip prologue+dispatch EXACT")
dump(0x439620, 0x120, "getters 0x439680 / 0x4396f0")
open(r"D:\XiuXian\_analysis\re\s41_fu.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
