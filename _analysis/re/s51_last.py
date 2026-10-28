# -*- coding: utf-8 -*-
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")
def dump(a, n, tag=""):
    W("--- %s 0x%08X ---" % (tag, a))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]

W("### every immediate 0x405 / 0x40B / 0x408 in .text (with mnemonic) ###")
for imm in (0x405, 0x40B, 0x408):
    W("--- imm 0x%X ---" % imm)
    pat = re.compile(re.escape(imm.to_bytes(4, "little")))
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
            if ins.mnemonic not in ("cmp", "push", "mov"): continue
            seen.add(va)
            W("   0x%08X off=0x%06X  %-22s %s %s" % (va, pe.va2off(va), ins.bytes.hex(), ins.mnemonic, ins.op_str))
            break
    W("  total %d" % len(seen))
W("")

dump(0x418F50, 0x120, "formatter 0x418F50 (used by 0x439E80)")
dump(0x471C60, 0x140, "0x471c60 (called from perform_use w/ count)")
open(r"D:\XiuXian\_analysis\re\s51_last.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
