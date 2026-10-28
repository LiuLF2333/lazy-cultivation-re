# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

W("### 0x4798B0..0x47A130 : every non-mov op + every push imm + every call ###")
for ins in disasm(pe, 0x4798B0, 0x890):
    m, o = ins[2], ins[3]
    if m == "call" or (m == "push" and o.startswith("0x")) or (m == "cmp" and "ptr [" in o) or (m == "mov" and "ptr [" in o and ", e" in o):
        W("  0x%08X  %-8s %s" % (ins[0], m, o))
open(r"D:\XiuXian\_analysis\re\s55_use.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
