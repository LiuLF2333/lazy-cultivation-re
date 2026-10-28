# -*- coding: utf-8 -*-
"""Map container offsets: for each call to a container-getter, print the
`add ecx, IMM` / `lea ecx,[reg+IMM]` immediately preceding it."""
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

def around(target, back=0x30, tag=""):
    W("=== call sites of 0x%08X (%s) ===" % (target, tag))
    for c in pe.find_calls_to(target):
        W("  -- site 0x%08X off=0x%06X --" % (c, pe.va2off(c)))
        for ins in disasm(pe, c-back, back):
            W("     0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
    W("")

around(0x439680, 0x30, "item field getter (int)")
around(0x4396f0, 0x30, "item field getter (str)")
around(0x438920, 0x20, "generic container find-key")
open(r"D:\XiuXian\_analysis\re\s33_containers.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
