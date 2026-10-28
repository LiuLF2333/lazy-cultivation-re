# -*- coding: utf-8 -*-
"""Scan .text for any instruction whose operand is the immediate 0x405 or 0x40B
(sub/cmp/add/mov/push/lea etc). Brute force with start-offset search."""
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]

def scan(imm, tag):
    W("=== all instructions with immediate 0x%X (%s) ===" % (imm, tag))
    pat = imm.to_bytes(4, "little")
    seen = set()
    for m in re.finditer(re.escape(pat), code):
        i = m.start()
        for st in range(max(0, i-7), i+1):
            va = TEXT_LO + st
            if va in seen: continue
            got = list(_md.disasm(code[st:st+15], va, count=1))
            if not got: continue
            ins = got[0]
            if ins.size != i - st + 4:
                continue
            if ("0x%x" % imm) in ins.op_str.lower() or ("0x%x" % imm) in ins.mnemonic.lower():
                seen.add(va)
                W("  0x%08X off=0x%06X  %-22s %s %s" % (va, pe.va2off(va), ins.bytes.hex(), ins.mnemonic, ins.op_str))
    W("")

scan(0x405, "WM 0x405")
scan(0x40B, "WM 0x40B")
scan(0x400, "0x400 base")
scan(0x41F, "0x41F bound")

open(r"D:\XiuXian\_analysis\re\s24_wm.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
