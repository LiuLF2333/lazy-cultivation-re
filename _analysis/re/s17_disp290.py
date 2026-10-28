# -*- coding: utf-8 -*-
"""Find all instructions in .text that mention a given disp32 memory operand."""
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]

def scan(disp, tag):
    W("=== instructions referencing +0x%X (%s) ===" % (disp, tag))
    pat = re.compile(re.escape((disp).to_bytes(4, "little")))
    seen = set()
    for m in pat.finditer(code):
        i = m.start()
        # candidate instruction start = i-3 (modrm+opcode before disp32)
        for st in (i-3, i-2):
            if st < 0: continue
            va = TEXT_LO + st
            if va in seen: continue
            got = list(_md.disasm(code[st:st+15], va, count=1))
            if not got: continue
            ins = got[0]
            if ins.size != i - st + 4:
                continue
            if ("+ 0x%x]" % disp) in ins.op_str or ("+ 0x%X]" % disp) in ins.op_str:
                seen.add(va)
                W("  0x%08X off=0x%06X  %-22s %s %s" % (va, pe.va2off(va), ins.bytes.hex(), ins.mnemonic, ins.op_str))
    W("")

scan(0x290, "item use counter")
scan(0x28C, "item flag 0x28c")

open(r"D:\XiuXian\_analysis\re\s17_disp290.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
