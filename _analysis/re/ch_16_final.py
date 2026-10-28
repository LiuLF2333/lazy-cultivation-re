# -*- coding: utf-8 -*-
"""Final: dump the real list-widget helpers + prove 0x40A620 is a CStringT-class dtor."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_16_final.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE(); raw = pe.raw

def dump(va, n, label=""):
    P("=" * 96)
    P("0x%08X (%s) off=0x%X" % (va, label, pe.va2off(va)))
    P("=" * 96)
    for ins in disasm(pe, va, n):
        P("   " + fmt(ins))
    P("")

P("#"*100); P("PROOF: 0x4D8BA0 (vtable[0] of the object at [ebp-0x184])"); P("#"*100)
dump(0x4D8BA0, 0x60, "vtable[0]")
dump(0x4D8BE0, 0x60, "next fn")
dump(0x40ABA0, 0x60, "0x40ABA0")
dump(0x40A3C0, 0x60, "vtbl 0x648258 [+0x104]")
dump(0x40A3E0, 0x60, "vtbl 0x648258 [+0x108]")
dump(0x40A400, 0x30, "called after 0x40A420(0x80) alloc")
dump(0x40A440, 0x20, "count")
dump(0x40A460, 0x30, "0x40A460")
dump(0x40A480, 0x40, "ctor for [ebp-0x820]")
dump(0x40A4E0, 0x40, "0x40A4E0")
dump(0x40A350, 0x40, "0x40A350")
dump(0x40A320, 0x40, "0x40A320")

P("#"*100); P("REAL widget helpers"); P("#"*100)
dump(0x4084E0, 0x240, "region with 0x408560/0x4085d0/0x4085f0")
dump(0x4084B0, 0x40, "")
dump(0x4D8595, 0x60, "called on [gameobj+0xac]")
dump(0x4CFA36, 0x60, "called on [gameobj+0xac]")
dump(0x4D23CA, 0x60, "called on [gameobj+0xac]")
dump(0x4D86CA, 0x60, "called on [gameobj+0xac]")

P("#"*100); P("Font face / class name strings"); P("#"*100)
for va in (0x6BC980,):
    P("  wide(0x%08X) = %r" % (va, pe.wide(va)))
    P("  raw = %s" % pe.bytes_at(va, 64).hex(" "))

P("#"*100); P("gap between 0x40A6F0 and 0x40A800 (unexplored helper zone)"); P("#"*100)
dump(0x40A720, 0x100, "0x40A720-0x40A820")
OUT.close()
print("ok")
