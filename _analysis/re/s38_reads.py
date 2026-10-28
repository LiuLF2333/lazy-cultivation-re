# -*- coding: utf-8 -*-
"""Find functions that READ both +0x278 and +0x294."""
import sys, io, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, _md
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
code = pe.raw[pe.va2off(TEXT_LO): pe.va2off(TEXT_HI)]

def refs(disp):
    res = {}
    pat = re.compile(re.escape(disp.to_bytes(4, "little")))
    for m in pat.finditer(code):
        i = m.start()
        for st in range(max(0, i-4), i+1):
            va = TEXT_LO + st
            got = list(_md.disasm(code[st:st+16], va, count=1))
            if not got: continue
            ins = got[0]
            if ins.size != i - st + 4: continue
            if ("+ 0x%x]" % disp) not in ins.op_str: continue
            if ins.mnemonic in ("mov", "movzx", "movsx", "cmp") or ins.mnemonic.startswith("cmp"):
                res[va] = (ins.bytes.hex(), ins.mnemonic, ins.op_str)
            break
    return res

a = refs(0x278)   # value1
b = refs(0x294)   # 从分类 / target attr
c = refs(0x290)   # use counter
W("reads/writes of 0x278: %d ; 0x294: %d ; 0x290: %d" % (len(a), len(b), len(c)))

def find_func(va, back=0x2000):
    for x in range(va-4, max(TEXT_LO, va-back), -1):
        if pe.bytes_at(x, 3) == b"\x55\x8b\xec":
            p1 = pe.bytes_at(x-1, 1)
            if p1 in (b"\xcc", b"\xc3"):
                return x
            p2 = pe.bytes_at(x-3, 2)
            if p2 == b"\xc2\x04" or pe.bytes_at(x-2,1) == b"\xc2":
                return x
    return None

W("")
W("### instructions touching 0x294 (item 从分类) ###")
for va in sorted(b):
    f = find_func(va)
    W("  0x%08X %-20s %s %s   func=%s" % (va, b[va][0], b[va][1], b[va][2], ("0x%08X" % f) if f else "?"))

W("")
W("### instructions touching 0x278 (item value1) ###")
for va in sorted(a):
    f = find_func(va)
    W("  0x%08X %-20s %s %s   func=%s" % (va, a[va][0], a[va][1], a[va][2], ("0x%08X" % f) if f else "?"))

# functions with both
fa = set(filter(None, (find_func(v) for v in a)))
fb = set(filter(None, (find_func(v) for v in b)))
W("")
W("### functions with BOTH 0x278 and 0x294: %s" % [hex(x) for x in sorted(fa & fb)])

open(r"D:\XiuXian\_analysis\re\s38_reads.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
