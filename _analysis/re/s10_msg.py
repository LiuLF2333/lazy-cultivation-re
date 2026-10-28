# -*- coding: utf-8 -*-
"""Find the message handler for WM 0x405 / 0x40b, and scan for type1 field reads."""
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

# 3D imm32 = cmp eax, imm32 ; 81 /7 = cmp [reg+disp], imm32 ; 3D variants
targets = {0x405:"0x405", 0x40b:"0x40b", 0x1d:"0x1d"}
code = pe.raw[pe.text()[0]:pe.text()[0]+pe.text()[2]]
T = IMAGE_BASE + pe.text()[1]

W("=== `cmp reg, 0x405` (3D 05 04 00 00 / 81 F8..) ===")
for i in range(len(code)-6):
    if code[i] == 0x3D:
        imm = struct.unpack_from("<I", code, i+1)[0]
        if imm in (0x405, 0x40b):
            W("  0x%08X cmp eax, 0x%X" % (T+i, imm))
    if code[i] == 0x81 and (code[i+1] & 0xF8) == 0xF8:
        imm = struct.unpack_from("<I", code, i+2)[0]
        if imm in (0x405, 0x40b):
            W("  0x%08X cmp r32, 0x%X" % (T+i, imm))
    if code[i] == 0x66 and code[i+1] == 0x3D:
        imm = struct.unpack_from("<H", code, i+2)[0]
        if imm in (0x405, 0x40b):
            W("  0x%08X cmp ax, 0x%X" % (T+i, imm))

# find all callees of 0x473490 / 0x473630 to see where 0x471bb0 leads
W("")
W("=== callers of 0x471bb0, 0x473630, 0x471c60, 0x4930a0, 0x43a460 ===")
for t in (0x471bb0, 0x473630, 0x471c60, 0x4930a0, 0x43a460, 0x416f90):
    W("  0x%08X -> %s" % (t, [hex(x) for x in pe.find_calls_to(t)]))

open(r"D:\XiuXian\_analysis\re\s10_msg.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
