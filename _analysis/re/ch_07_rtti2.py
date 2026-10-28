# -*- coding: utf-8 -*-
"""Locate RTTI structures by searching for type-descriptor VAs."""
import sys, struct, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_07_rtti2.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE(); raw = pe.raw

names = {}
for s in pe.sections:
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    i = a
    while i < b - 8:
        if raw[i:i+4] in (b".?AV", b".?AU"):
            j = i; ch = []
            while j < b and 0x20 <= raw[j] < 0x7f:
                ch.append(chr(raw[j])); j += 1
            if raw[j] == 0 and len(ch) > 5:
                names[pe.off2va(i)] = "".join(ch); i = j + 1; continue
        i += 1

# A TypeDescriptor starts 8 bytes before the name: {vfptr, spare, name}
td2name = {nva - 8: nm for nva, nm in names.items()}

# Search .rdata/.data for dwords equal to a type-descriptor VA
hits = []
for s in pe.sections:
    if s["name"] not in (".rdata", ".data"):
        continue
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    for i in range(a, b - 4, 4):
        v = struct.unpack_from("<I", raw, i)[0]
        if v in td2name:
            hits.append((pe.off2va(i), v, td2name[v]))
P("dword hits pointing at TypeDescriptors: %d" % len(hits))
for h in hits[:40]:
    P("   at 0x%08X -> 0x%08X %s" % h)

P("")
P("#" * 100)
P("Dump 0x30 bytes before each hit (candidate RTTICompleteObjectLocator)")
P("#" * 100)
for va, v, nm in hits[:20]:
    P("---- hit 0x%08X  (%s)" % (va, nm))
    for d in range(-0x20, 0x10, 4):
        w = pe.u32(va + d)
        P("      [%+#06x] 0x%08X" % (d, w))
    P("")

P("")
P("#" * 100)
P("Look for the literal COL pattern anywhere: sig=1,off=0,cd,ptd,pcd")
P("#" * 100)
cnt = 0
for s in pe.sections:
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    for i in range(a, b - 0x14, 4):
        sig, off = struct.unpack_from("<II", raw, i)
        if sig == 1 and off == 0:
            v = struct.unpack_from("<I", raw, i + 12)[0]
            if v in td2name:
                cnt += 1
                P("   COL@0x%08X -> %s" % (pe.off2va(i), td2name[v]))
P("count=%d" % cnt)

P("")
P("#" * 100)
P("Sample RTTI names (first 60 in .rdata order)")
P("#" * 100)
for nva in sorted(names)[:60]:
    P("   0x%08X  %s" % (nva, names[nva]))
OUT.close()
print("ok")
