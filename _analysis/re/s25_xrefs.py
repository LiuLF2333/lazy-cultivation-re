# -*- coding: utf-8 -*-
"""General xref: find any dword==VA inside .text and disassemble the containing instr."""
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]

def xrefs(va):
    pat = va.to_bytes(4, "little")
    res = []
    seen = set()
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
                seen.add(sva)
                res.append((sva, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    return res

def func_head(va, back=0x1200):
    """Scan backwards for a plausible prologue: 55 8B EC preceded by int3/ret."""
    best = None
    for a in range(va - 4, max(TEXT_LO, va - back), -1):
        if pe.bytes_at(a, 3) == b"\x55\x8b\xec":
            prev = pe.bytes_at(a-1, 1)
            if prev in (b"\xcc", b"\xc3", b"\xc2") or pe.bytes_at(a-2,1)==b"\xc2":
                best = a
                break
    return best

NEEDLES = []
for s in ["所有基础属性增加", "增加年龄随机奖励基础属性", "机缘永久增加了", "所有基础属性奖励",
          "你服用了", "最多可服用", "服用过多后将无效", "使用后立即增加使用者", "无法服用",
          "服用后使", "属性异常", "无效属性", "增加了", "服用后立即增加使用者",
          "服用后立即增加使用者的随机基础属性", "服用后能提高一定的境界值", "当前属性",
          "修为增加了", "亲密增加了", "界点增加了"]:
    b = s.encode("utf-16-le")
    st = 0
    while True:
        i = pe.raw.find(b, st)
        if i < 0: break
        va = pe.off2va(i)
        if va: NEEDLES.append((s, va))
        st = i + 1

for s, va in NEEDLES:
    xs = xrefs(va)
    W("%r  0x%08X  xrefs=%d" % (s, va, len(xs)))
    for (sva, by, mn, ops) in xs:
        fh = func_head(sva)
        W("    0x%08X %-20s %s %s   funchead=%s" % (sva, by, mn, ops, ("0x%08X" % fh) if fh else "?"))
    W("")

open(r"D:\XiuXian\_analysis\re\s25_xrefs.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
