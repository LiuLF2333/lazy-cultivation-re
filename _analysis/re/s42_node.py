# -*- coding: utf-8 -*-
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")
def dump(a, n, tag=""):
    W("--- %s 0x%08X .. 0x%08X ---" % (tag, a, a+n))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

# 1) find_key / container primitives
dump(0x438920, 0xC0, "find_key 0x438920")
dump(0x438560, 0x60, "0x438560")
dump(0x438990, 0x60, "0x438990 put")
dump(0x438AC0, 0x60, "0x438AC0")

# 2) every store into the ItemTable row in loader 0x42A0B0
W("### all '[reg+disp], eax/edx/ecx' stores in ItemTable loader 0x42A0B0..0x42A760 ###")
for ins in disasm(pe, 0x42A0B0, 0x6B0):
    if ins[2] == "mov" and "ptr [" in ins[3] and "], e" in ins[3]:
        W("  0x%08X  %s %s" % (ins[0], ins[2], ins[3]))
W("")
W("### push 0x2f4 / push 0x2b4 / push imm alloc sites ###")
TEXT_LO, TEXT_HI = 0x401000, 0x644800
for ins in disasm(pe, TEXT_LO, TEXT_HI-TEXT_LO):
    if ins[2] == "push" and ins[3] in ("0x2f4", "0x2b4", "0x2f0", "0x300"):
        W("  0x%08X  push %s" % (ins[0], ins[3]))
open(r"D:\XiuXian\_analysis\re\s42_node.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
