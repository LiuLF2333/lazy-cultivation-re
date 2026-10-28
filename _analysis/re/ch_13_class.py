# -*- coding: utf-8 -*-
"""Identify classes by their vtables/ctors and locate the real selection path."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_13_class.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE(); raw = pe.raw

# ---- full vtable dumps ----
def vtdump(vt, n=64):
    P("---- vtable 0x%08X (%d slots)" % (vt, n))
    for i in range(n):
        f = pe.u32(vt + i*4)
        if f is None: break
        P("      [+0x%03X] 0x%08X" % (i*4, f))
    P("")

P("#"*100); P("FULL VTABLE DUMPS"); P("#"*100)
for vt in (0x648258, 0x649320, 0x693014, 0x6930A0, 0x693000):
    vtdump(vt, 80)

P("#"*100)
P("WHO SETS THESE VTABLES (mov dword ptr [reg], imm32 = C7 00/01/.. imm32)")
P("#"*100)
TRP, TVA, TRS = pe.text()
text = raw[TRP:TRP+TRS]
for imm in (0x648258, 0x649320, 0x693014, 0x6930A0, 0x693000, 0x69301C):
    b = struct.pack("<I", imm)
    hits = []
    st = 0
    while True:
        i = text.find(b, st)
        if i < 0: break
        op = text[max(0, i-2):i]
        hits.append((IMAGE_BASE + TVA + i - 2, op.hex()))
        st = i + 1
    P("  imm 0x%08X : %s" % (imm, ", ".join("0x%X[%s]" % h for h in hits[:20]) or "-"))
    for va, op in hits[:8]:
        if op.endswith("c700") or op.endswith("c701") or op.endswith("c702") or op.endswith("c703") or op.endswith("c706") or op.endswith("c707"):
            P("      -> ctor candidate 0x%08X" % va)
            for ins in disasm(pe, va, 0x60):
                P("           " + fmt(ins))
            P("")

P("#"*100)
P("0x4216B0 caller census (sample): instruction 2 before the call")
P("#"*100)
from collections import Counter
sites = pe.find_calls_to(0x4216B0)
P("total callers of 0x4216B0 = %d" % len(sites))
# what is `this`? look at the lea ecx right before
cnt = Counter()
def ins_before(va, n=4):
    for back in range(1, 60):
        ins = list(disasm(pe, va-back, back+16, resync=False))
        if any(i[0] == va for i in ins):
            seq = [i for i in ins if i[0] < va]
            if len(seq) >= n:
                return seq[-n:]
    return []
for s in sites[:400]:
    seq = ins_before(s, 3)
    if seq:
        cnt[" | ".join("%s %s" % (i[2], i[3]) for i in seq)] += 1
for k, c in cnt.most_common(12):
    P("   x%-4d %s" % (c, k))

P("")
P("#"*100)
P("0x421730 caller census")
P("#"*100)
sites2 = pe.find_calls_to(0x421730)
P("total callers of 0x421730 = %d" % len(sites2))
cnt2 = Counter()
for s in sites2[:400]:
    seq = ins_before(s, 6)
    if seq:
        cnt2[" | ".join("%s %s" % (i[2], i[3]) for i in seq)] += 1
for k, c in cnt2.most_common(15):
    P("   x%-4d %s" % (c, k))
OUT.close()
print("ok")
