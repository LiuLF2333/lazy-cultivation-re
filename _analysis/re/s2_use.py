# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

def dump(a, n, tag=""):
    W("--- %s 0x%08X .. 0x%08X ---" % (tag, a, a+n))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

dump(0x476740, 0x420, "use_item 0x476740")
dump(0x473490, 0x300, "perform_use 0x473490")

# find wide 'ItemTable' etc
W("=== wide strings containing Table ===")
import re
for s in ("ItemTable","GameAttribStringTable","ItemTable.gjd"):
    b = s.encode("utf-16-le")
    st=0; hits=[]
    while True:
        i = pe.raw.find(b, st)
        if i<0: break
        va = pe.off2va(i)
        if va: hits.append(va)
        st=i+1
    W("  %r -> %s" % (s, [hex(v) for v in hits]))
    b2 = s.encode("gbk")
    st=0; hits2=[]
    while True:
        i = pe.raw.find(b2, st)
        if i<0: break
        va = pe.off2va(i)
        if va: hits2.append(va)
        st=i+1
    W("  gbk %r -> %s" % (s, [hex(v) for v in hits2]))

open(r"D:\XiuXian\_analysis\re\s2_use.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
