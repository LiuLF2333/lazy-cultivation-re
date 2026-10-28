# -*- coding: utf-8 -*-
"""Dump sub-functions referenced by the candidates, plus the known call-site regions."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_02_body.txt", "w", encoding="utf-8")
def P(*a):
    OUT.write(" ".join(str(x) for x in a) + "\n")

pe = PE()

def dump(va, n, label=""):
    P("=" * 96)
    P("0x%08X  (%s)  off=0x%X" % (va, label, pe.va2off(va)))
    P("=" * 96)
    for ins in disasm(pe, va, n):
        P("   " + fmt(ins))
    P("")

dump(0x421360, 0x100, "called by ctor with title arg -> returns al")
dump(0x421690, 0x100, "called by ctor when al==0")
dump(0x40A560, 0x70,  "called by ctor: ecx=this, arg=eax from 0x40A5D0")
dump(0x40A5D0, 0x90,  "no-arg, returns eax")
dump(0x4219B0, 0x120, "called by add-entry: ecx=arg1, +8,+0xc")
dump(0x4041A0, 0x60,  "called by add-entry")
dump(0x40A9B0, 0x40,  "sub")
dump(0x40A9D0, 0x70,  "sub")
OUT.close()
print("ok")
