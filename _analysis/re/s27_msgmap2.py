# -*- coding: utf-8 -*-
"""AFX_MSGMAP_ENTRY with nMessage=0x405/0x40B, nCode=nID=nLastID=0, any nSig, pfn in .text."""
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
for msg in (0x405, 0x40B, 0x403, 0x404, 0x400, 0x401, 0x402, 0x406, 0x407, 0x408, 0x409, 0x40A, 0x40C, 0x40D):
    pat = struct.pack("<IIII", msg, 0, 0, 0)
    st = 0; found=[]
    while True:
        i = pe.raw.find(pat, st)
        if i < 0: break
        va = pe.off2va(i)
        if va is not None:
            sig = pe.u32(va+16); pfn = pe.u32(va+20)
            if pfn and TEXT_LO <= pfn < TEXT_HI:
                found.append((va, sig, pfn))
        st = i+1
    if found:
        W("msg 0x%X:" % msg)
        for (va, sig, pfn) in found:
            W("   entry 0x%08X  sig=0x%X  pfn=0x%08X" % (va, sig, pfn))

W("")
W("=== all message-map entries with nCode=0,nID=0,nLastID=0 and pfn in .text (msg 0x400..0x500) ===")
for msg in range(0x400, 0x500):
    pat = struct.pack("<IIII", msg, 0, 0, 0)
    st = 0
    while True:
        i = pe.raw.find(pat, st)
        if i < 0: break
        va = pe.off2va(i)
        if va is not None:
            sig = pe.u32(va+16); pfn = pe.u32(va+20)
            if pfn and TEXT_LO <= pfn < TEXT_HI and sig in range(0, 0x100):
                W("   msg 0x%X entry 0x%08X sig=0x%X pfn=0x%08X" % (msg, va, sig, pfn))
        st = i+1

open(r"D:\XiuXian\_analysis\re\s27_msgmap2.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
