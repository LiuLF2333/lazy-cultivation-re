# -*- coding: utf-8 -*-
"""Dump function heads of the candidate chooser functions + call-site census."""
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_heads.txt", "w", encoding="utf-8")

def P(*a):
    OUT.write(" ".join(str(x) for x in a) + "\n")

pe = PE()
P("sections:")
for s in pe.sections:
    P("  %-8s VA 0x%-8X vsize 0x%-8X rawptr 0x%-8X rawsize 0x%-8X" %
      (s["name"], 0x400000 + s["va"], s["vsize"], s["rawptr"], s["rawsize"]))
P("")

TARGETS = [0x4216B0, 0x421730, 0x40A620, 0x40A600, 0x40AA40, 0x40A6F0]
for t in TARGETS:
    P("=" * 100)
    P("FUNCTION HEAD 0x%08X   (file off 0x%X)" % (t, pe.va2off(t)))
    P("=" * 100)
    for ins in disasm(pe, t, 0x140):
        P("   " + fmt(ins))
    P("")

P("#" * 100)
P("CALL-SITE CENSUS")
P("#" * 100)
for t in TARGETS:
    hits = pe.find_calls_to(t)
    P("")
    P("calls to 0x%08X : %d sites" % (t, len(hits)))
    for h in hits:
        P("    0x%08X" % h)

P("")
P("#" * 100)
P("OTHER REFERENCES (push imm32 of the VA, i.e. vtables / fn ptrs)")
P("#" * 100)
for t in TARGETS:
    hits = pe.find_dword_va(t)
    P("dword 0x%08X at: %s" % (t, ", ".join("0x%08X" % h for h in hits[:40])))

OUT.close()
print("done")
