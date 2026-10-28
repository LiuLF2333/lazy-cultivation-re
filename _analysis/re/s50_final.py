# -*- coding: utf-8 -*-
import sys, io, csv
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

def wstr(va, maxb=0x300):
    b = pe.bytes_at(va, maxb)
    z = b.find(b"\x00\x00")
    if z >= 0: b = b[:z+1]
    if len(b) % 2: b += b"\x00"
    return b.decode("utf-16-le", "replace")

W("full 0x6814C4: %r" % wstr(0x6814C4))
W("full 0x6815C4: %r" % wstr(0x6815C4))
W("full 0x6816FC: %r" % wstr(0x6816FC))
W("")

rows = list(csv.reader(io.open(r"D:\XiuXian\_analysis\decoded\ItemTable.txt", encoding="utf-8")))
h = rows[0]
W("cols: %s" % list(enumerate(h)))
W("")
W("### all type1 in (110,132) rows ###")
for r in rows[1:]:
    if len(r) < 18: continue
    try: t = int(r[13])
    except Exception: continue
    if t in (110, 132):
        W("  ID=%s name=%s 从分类(col5)=%s 品质=%s 等级=%s 最大叠加=%s type1=%s value1=%s type2=%s value2=%s" %
          (r[0], r[1], r[5], r[6], r[7], r[12], r[13], r[14], r[15], r[16]))
W("")
def dump(a, n, tag=""):
    W("--- %s 0x%08X ---" % (tag, a))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")
dump(0x439E80, 0x90, "predicate 0x439E80")
dump(0x4397A0, 0x70, "0x4397A0")
dump(0x4395C0, 0x70, "0x4395C0 head")
open(r"D:\XiuXian\_analysis\re\s50_final.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
