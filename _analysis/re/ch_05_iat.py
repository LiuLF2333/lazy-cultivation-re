# -*- coding: utf-8 -*-
"""Resolve specific IAT slots to imported function names."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_05_iat.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")

pe = PE()
raw = pe.raw

def rva2off(rva):
    for s in pe.sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + (rva - s["va"])
    return None

pe_off = pe.pe_off
opt = pe.opt
dd = opt + 96          # data directories (PE32: offset 96 in optional header)
imp_rva, imp_sz = struct.unpack_from("<II", raw, dd + 1 * 8)
P("Import directory RVA 0x%X size 0x%X -> off 0x%X" % (imp_rva, imp_sz, rva2off(imp_rva)))

iat = {}   # IAT VA -> (dll, name)
o = rva2off(imp_rva)
i = 0
while True:
    oft, ts, fc, namerva, firstthunk = struct.unpack_from("<IIIII", raw, o + i * 20)
    if namerva == 0 and firstthunk == 0:
        break
    noff = rva2off(namerva)
    dll = raw[noff:raw.index(b"\0", noff)].decode("latin1")
    toff = rva2off(oft) if oft else rva2off(firstthunk)
    j = 0
    while True:
        v = struct.unpack_from("<I", raw, toff + j * 4)[0]
        if v == 0:
            break
        if v & 0x80000000:
            nm = "ORD_%d" % (v & 0xFFFF)
        else:
            fo = rva2off(v)
            nm = raw[fo + 2:raw.index(b"\0", fo + 2)].decode("latin1")
        iat[IMAGE_BASE + firstthunk + j * 4] = (dll, nm)
        j += 1
    i += 1

P("total IAT slots decoded: %d" % len(iat))
P("")
SLOTS = [0x6451D0, 0x6457A8, 0x6456F4, 0x6451C0, 0x6456F8, 0x6451C4,
         0x6451C8, 0x6451CC, 0x6451D4, 0x6451D8]
for s in SLOTS:
    P("IAT 0x%08X : %s" % (s, iat.get(s, "<not an IAT slot>")))

P("")
P("All slots in 0x6451A0..0x6451F0 and 0x6456E0..0x6457C0:")
for s in sorted(iat):
    if 0x6451A0 <= s <= 0x6451F0 or 0x6456E0 <= s <= 0x6457C0:
        P("   0x%08X  %-14s %s" % (s, iat[s][0], iat[s][1]))
OUT.close()
print("ok")
