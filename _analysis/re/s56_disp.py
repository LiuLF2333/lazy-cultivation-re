# -*- coding: utf-8 -*-
"""Find every site matching the tooltip's type1 dispatch shape:
   sub r32,0x64  ... cmp r32,0x20 ... ja ... jmp [r*4+disp]"""
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]

sub_pats = [b"\x83\xe8\x64", b"\x83\xe9\x64", b"\x83\xea\x64", b"\x83\xeb\x64",
            b"\x2d\x64\x00\x00\x00", b"\x83\xee\x64", b"\x83\xef\x64",
            b"\x83\xec\x64", b"\x83\xed\x64"]
W("### sites with sub reg,0x64 followed within 0x40 bytes by cmp ...,0x20 ###")
hits = 0
for pat in sub_pats:
    st = 0
    while True:
        i = code.find(pat, st)
        if i < 0: break
        st = i + 1
        va = TEXT_LO + i
        window = code[i:i+0x50]
        if b"\x20" not in window:
            continue
        # disassemble the window and look for cmp X,0x20 / 0x21 / 0x2c / 0x12f / 0x12c
        ins_list = list(disasm(pe, va, 0x50))
        found = []
        for ins in ins_list:
            if ins[2] == "cmp" and ins[3].split(",")[-1].strip() in ("0x20", "0x21", "0x2c", "0x12f", "0x12c", "0xfe", "0x64"):
                found.append(ins)
        if found:
            hits += 1
            W("")
            W("  *** 0x%08X (off 0x%06X)" % (va, pe.va2off(va)))
            for ins in ins_list[:24]:
                W("      0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
W("")
W("total %d candidate sites" % hits)
open(r"D:\XiuXian\_analysis\re\s56_disp.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
