# -*- coding: utf-8 -*-
"""Verify raw bytes; find callers of the enclosing functions; hunt the real list widget."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_14_verify.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE(); raw = pe.raw

P("#"*100); P("RAW BYTE CHECK (guards against capstone misdecode)"); P("#"*100)
for va, n, lb in [(0x4219B0, 0x18, "0x4219B0"), (0x4041A0, 0x14, "0x4041A0"),
                  (0x40AA40, 0x14, "0x40AA40"), (0x40A560, 0x64, "0x40A560"),
                  (0x421730, 0x34, "0x421730")]:
    P("  %s : %s" % (lb, pe.bytes_at(va, n).hex(" ")))
P("")
P("  0x4041A0 disasm resync=False:")
for ins in disasm(pe, 0x4041A0, 0x14, resync=False):
    P("     " + fmt(ins))
P("")
P("  0x4219B0 disasm resync=False:")
for ins in disasm(pe, 0x4219B0, 0x18, resync=False):
    P("     " + fmt(ins))

P("")
P("#"*100)
P("CALLERS of the enclosing functions 0x49FCD0 and of 0x4081F0-ish")
P("#"*100)
for f in (0x49FCD0,):
    hits = pe.find_calls_to(f)
    P("  callers of 0x%08X : %d" % (f, len(hits)))
    for h in hits:
        P("     0x%08X" % h)
        for ins in disasm(pe, h - 0x40, 0x50):
            P("        " + fmt(ins))
        P("")

P("#"*100)
P("Find enclosing function of the 遗忘技能 site 0x408225")
P("#"*100)
def is_pad(v): return v in (0xCC, 0x90)
TRP, TVA, TRS = pe.text()
def func_start(va):
    off = pe.va2off(va)
    for back in range(2, 0x6000):
        o = off - back
        if o < TRP: break
        if raw[o:o+3] == b"\x55\x8b\xec" and o-2 >= TRP and is_pad(raw[o-2]) and is_pad(raw[o-1]):
            return pe.off2va(o)
    return None
st = func_start(0x408225)
P("  enclosing function: 0x%X" % st)
for ins in disasm(pe, st, 0x900):
    P("   " + fmt(ins))
OUT.close()
print("ok", hex(func_start(0x408225)))
