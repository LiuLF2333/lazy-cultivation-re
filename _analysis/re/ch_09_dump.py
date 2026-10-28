# -*- coding: utf-8 -*-
"""Verify the CString hypothesis: dump the 0x40A000..0x40AC00 and 0x421200..0x422000 regions."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()

def dumpfile(path, ranges):
    OUT = open(path, "w", encoding="utf-8")
    def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
    for st, en, label in ranges:
        P("#" * 100)
        P("# %s   0x%08X .. 0x%08X" % (label, st, en))
        P("#" * 100)
        for ins in disasm(pe, st, en - st):
            P(fmt(ins))
        P("")
    OUT.close()

dumpfile(r"D:\XiuXian\_analysis\re\out\ch_09_cstring_body.txt",
         [(0x40A000, 0x40AC00, "ATL CStringT + CWindow wrapper region")])

dumpfile(r"D:\XiuXian\_analysis\re\out\ch_10_4212_body.txt",
         [(0x421200, 0x422000, "0x4212xx region (ctor / title-setter family)")])

dumpfile(r"D:\XiuXian\_analysis\re\out\ch_11_misc.txt",
         [(0x4CF7E0, 0x4CF880, "0x4CF829"),
          (0x4CEB80, 0x4CED20, "AtlThrow / CAtlException"),
          (0x40A800, 0x40A830, "0x40A800 - writes CString.m_pchData"),
          (0x435E60, 0x436000, "0x435EB0 5-arg helper"),
          (0x4A17A0, 0x4A1840, "0x4A17C0"),
          (0x40A100, 0x40A180, "0x40A110 / 0x40A130"),
          (0x40AD80, 0x40ADC0, "0x40AD90"),
          ])
print("ok")
