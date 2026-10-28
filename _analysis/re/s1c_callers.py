# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

for tgt,name in ((0x4183B0,"tooltip_builder"),):
    hits = pe.find_calls_to(tgt)
    W("=== callers of 0x%08X (%s): %d ===" % (tgt, name, len(hits)))
    for h in hits:
        W("  call site 0x%08X off=0x%06X" % (h, pe.va2off(h)))

W("")
W("=== context around each caller ===")
for h in pe.find_calls_to(0x4183B0):
    W("--- around 0x%08X ---" % h)
    for ins in disasm(pe, h-0x50, 0x60):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

# Also head of 0x426240 and 0x4261d0
W("=== 0x426240 head ===")
for ins in disasm(pe, 0x426240, 0x90):
    W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))

open(r"D:\XiuXian\_analysis\re\s1c_callers.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
