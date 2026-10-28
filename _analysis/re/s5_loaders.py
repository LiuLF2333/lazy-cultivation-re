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

dump(0x42A000, 0x260, "ItemTable loader ref @0x42a0e1")
dump(0x42CB00, 0x200, "GameAttribStringTable loader ref @0x42cb49")

W("=== wide strings (aligned, raw) 0x6883e0..0x688500 ===")
for va in range(0x6883e0, 0x688500, 2):
    w = pe.wide(va)
    if w and len(w) > 1 and all(ord(c) >= 0x20 for c in w):
        W("  0x%08X %r" % (va, w))

W("")
W("=== raw hex 0x68a940..0x68aa20 ===")
b = pe.bytes_at(0x68a940, 0xE0)
W(b.hex())
W("--- aligned wide decode ---")
for va in range(0x68a940, 0x68aa20, 2):
    w = pe.wide(va, 80)
    if w and all(ord(c) >= 0x20 for c in w) and len(w) >= 2:
        W("  0x%08X %r" % (va, w))
        break

open(r"D:\XiuXian\_analysis\re\s5_loaders.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
