# -*- coding: utf-8 -*-
"""Find MFC AFX_MSGMAP_ENTRY tables by locating dword 0x405 / 0x40b and dumping
the surrounding 24-byte entries."""
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

for val in (0x405, 0x40B, 0x403, 0x404):
    W("=== dword 0x%X occurrences (VA) ===" % val)
    vs = pe.find_dword_va(val)
    W("  %s" % [hex(v) for v in vs])
    for v in vs:
        # assume it is offset 0 of an entry, and offset 0 of entries is nMessage.
        # dump -0x30..+0x30 as dwords
        W("  --- around 0x%08X ---" % v)
        for k in range(-4, 5):
            W("      [+0x%+03X] 0x%08X" % (k*4, pe.u32(v+k*4)))
    W("")

open(r"D:\XiuXian\_analysis\re\s12_msgmap.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
