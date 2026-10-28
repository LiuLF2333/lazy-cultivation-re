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

for t in (0x426240, 0x4261d0, 0x4262b0, 0x4310d0):
    W("callers of 0x%08X: %s" % (t, [hex(x) for x in pe.find_calls_to(t)]))

# imports
W("")
W("=== imports in .rdata (look for rand) ===")
import re
b = pe.raw
for m in re.finditer(rb"rand\x00", b):
    va = pe.off2va(m.start())
    if va: W("  'rand' at 0x%08X" % va)
for name in (b"srand", b"GetTickCount", b"time"):
    for m in re.finditer(re.escape(name)+rb"\x00", b):
        va = pe.off2va(m.start())
        if va: W("  %r at 0x%08X" % (name, va))

# IAT slots referencing these names
W("")
W("=== IAT slots (dword refs) ===")
for m in re.finditer(rb"rand\x00", b):
    va = pe.off2va(m.start())
    if va is None: continue
    for d in pe.find_dword_va(va):
        W("  name VA 0x%08X referenced from 0x%08X" % (va, d))

open(r"D:\XiuXian\_analysis\re\s14_rand.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
