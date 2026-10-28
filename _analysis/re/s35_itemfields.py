# -*- coding: utf-8 -*-
"""Find writes to +0x294, +0x278, +0x28C on the item object."""
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]

def scan(disp, tag, only_store=False):
    W("=== +0x%X (%s) ===" % (disp, tag))
    pat = re.compile(re.escape(disp.to_bytes(4, "little")))
    seen = set()
    for m in pat.finditer(code):
        i = m.start()
        for st in range(max(0, i-4), i+1):
            va = TEXT_LO + st
            if va in seen: continue
            got = list(_md.disasm(code[st:st+16], va, count=1))
            if not got: continue
            ins = got[0]
            if ins.size != i - st + 4: continue
            if ("+ 0x%x]" % disp) not in ins.op_str: continue
            seen.add(va)
            W("  0x%08X off=0x%06X  %-22s %s %s" % (va, pe.va2off(va), ins.bytes.hex(), ins.mnemonic, ins.op_str))
    W("")

scan(0x294, "item 从分类/target attr")
scan(0x278, "item value1")
scan(0x28C, "item kind")

open(r"D:\XiuXian\_analysis\re\s35_itemfields.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
