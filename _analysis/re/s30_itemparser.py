# -*- coding: utf-8 -*-
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")
def dump(a, n, tag=""):
    W("--- %s 0x%08X .. 0x%08X ---" % (tag, a, a+n))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]
def xrefs(va):
    pat = va.to_bytes(4, "little"); res=[]; seen=set()
    for m in re.finditer(re.escape(pat), code):
        i = m.start()
        for st in range(max(0, i-8), i+1):
            sva = TEXT_LO + st
            if sva in seen: continue
            got = list(_md.disasm(code[st:st+16], sva, count=1))
            if not got: continue
            ins = got[0]
            if ins.size != i - st + 4: continue
            if ("0x%x" % va) in ins.op_str.lower():
                seen.add(sva); res.append((sva, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    return res

for va, nm in ((0x683360,"'ItemTable'"), (0x68337C,"'Data/ItemTable.gjd'"), (0x6833A8,"'EquipExDataTable'")):
    W("### xrefs to 0x%08X %s" % (va, nm))
    for (sva, by, mn, ops) in xrefs(va):
        W("   0x%08X %-20s %s %s" % (sva, by, mn, ops))
    W("")

W("### full dump around 0x42A0A0..0x42A120")
dump(0x42A0A0, 0x90, "ItemTable ref site")
W("### EquipExDataTable loader (~0x42A740 area, look backwards)")
dump(0x42A5C0, 0x1A0, "EquipEx loader")

open(r"D:\XiuXian\_analysis\re\s30_itemparser.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
