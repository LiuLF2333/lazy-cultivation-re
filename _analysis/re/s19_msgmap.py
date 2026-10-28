# -*- coding: utf-8 -*-
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
W("=== AFX_MSGMAP_ENTRY pattern: msg,0,0,0,0xFFFFFFFF,pfn ===")
for msg in (0x405, 0x40B, 0x403, 0x404, 0x406):
    pat = struct.pack("<IIIII", msg, 0, 0, 0, 0xFFFFFFFF)
    st = 0; hits=[]
    while True:
        i = pe.raw.find(pat, st)
        if i < 0: break
        va = pe.off2va(i)
        if va:
            pfn = pe.u32(va+20)
            hits.append((va, pfn))
        st = i+1
    W("  msg 0x%X -> %s" % (msg, [(hex(a), hex(b) if b else None) for a,b in hits]))

W("")
W("=== all AFX_MSGMAP_ENTRY-like entries with nSig==0xFFFFFFFF or 0xFFFFFFFE ===")
cnt = 0
for s in pe.sections:
    base = IMAGE_BASE + s["va"]
    n = s["rawsize"]//4 - 6
    for i in range(n):
        va = base + i*4
        sig = pe.u32(va+16)
        if sig in (0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD):
            msg = pe.u32(va); code = pe.u32(va+4); nid = pe.u32(va+8); last = pe.u32(va+12); pfn = pe.u32(va+20)
            if pfn and TEXT_LO <= pfn < TEXT_HI:
                cnt += 1
                W("  0x%08X msg=0x%X code=%d id=0x%X last=0x%X sig=0x%X pfn=0x%X" % (va, msg, code, nid, last, sig, pfn))
W("total %d" % cnt)

open(r"D:\XiuXian\_analysis\re\s19_msgmap.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
