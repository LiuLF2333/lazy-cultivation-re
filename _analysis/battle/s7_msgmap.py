# -*- coding: utf-8 -*-
"""Find AFX_MSGMAP_ENTRY records for WM_TIMER (0x113) and list handlers."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
p = PE(r"D:\XiuXian\懒人修仙传.exe")
d = p.raw

entries = []
for s in p.sections:
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    i = a
    while i + 24 <= b:
        msg, code, nid, nlast, sig, pfn = struct.unpack_from("<IIIIII", d, i)
        if msg == 0x113 and code == 0 and nid == 0 and nlast == 0 and 0x401000 <= pfn < 0x650000:
            entries.append((p.off2va(i), sig, pfn))
        i += 4

print("WM_TIMER message-map entries:", len(entries))
for va, sig, pfn in entries:
    print("  entry 0x%08X sig=0x%X pfn=0x%08X" % (va, sig, pfn))

# also all entries whose handler equals functions of interest
for target in (0x4C2A90, 0x4C2A50, 0x4C2900, 0x4C2980):
    hits = []
    i = 0
    while True:
        i = d.find(struct.pack("<I", target), i)
        if i < 0:
            break
        hits.append(p.off2va(i))
        i += 1
    print("raw dword occurrences of 0x%08X: %s" % (target, [hex(h) if h else None for h in hits]))
