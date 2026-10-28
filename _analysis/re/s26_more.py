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
    pat = va.to_bytes(4, "little")
    res = []; seen=set()
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

W("### wide strings windows (raw aligned decode) ###")
for lo, hi in ((0x680A60,0x680C00), (0x685DE0,0x686060), (0x688BA0,0x688C00),
               (0x68E740,0x68E7C0), (0x680300,0x680360), (0x6879A0,0x687A00),
               (0x689530,0x689660), (0x68BEC0,0x68BF00)):
    W("-- 0x%08X..0x%08X --" % (lo,hi))
    va = lo
    while va < hi:
        w = pe.wide(va, 200)
        if w and len(w) > 3 and all(ord(c) >= 0x20 for c in w):
            W("   0x%08X %r  xrefs=%s" % (va, w, [hex(x[0]) for x in xrefs(va)]))
            va += (len(w)+1)*2
        else:
            va += 2

dump(0x417E40, 0x100, "无效属性 fn")
dump(0x416F90, 0x100, "416f90")
W("### refs to 0x6c8878 (attr string table) ###")
for ins in disasm(pe, 0x401000, 0):
    pass
for m in re.finditer(re.escape((0x6C8878).to_bytes(4,"little")), code):
    i = m.start()
    for st in range(max(0,i-8), i+1):
        got = list(_md.disasm(code[st:st+16], TEXT_LO+st, count=1))
        if got and got[0].size == i-st+4 and "0x6c8878" in got[0].op_str.lower():
            W("   0x%08X %-20s %s %s" % (TEXT_LO+st, got[0].bytes.hex(), got[0].mnemonic, got[0].op_str))
            break

open(r"D:\XiuXian\_analysis\re\s26_more.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
