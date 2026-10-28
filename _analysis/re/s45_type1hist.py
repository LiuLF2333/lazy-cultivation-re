# -*- coding: utf-8 -*-
import sys, io, csv, collections
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

rows = list(csv.reader(io.open(r"D:\XiuXian\_analysis\decoded\ItemTable.txt", encoding="utf-8")))
hdr = rows[0]
W("header: %s" % hdr)
idx = {h: i for i, h in enumerate(hdr)}
t1 = collections.Counter()
for r in rows[1:]:
    if len(r) <= idx["type1"]:
        continue
    try:
        t1[int(r[idx["type1"]])] += 1
    except Exception:
        pass
W("distinct type1 values: %s" % sorted(t1))
W("min=%d max=%d" % (min(t1), max(t1)))
W("histogram idx (type1-1, value, count):")
for k in sorted(t1):
    W("   type1=%4d count=%d" % (k, t1[k]))
W("")
W("### max type1-1 = %d ; 0x12f=%d 0xfe=%d 0x130=%d 0xc5=%d 0x258=%d" % (max(t1)-1, 0x12f, 0xfe, 0x130, 0xc5, 0x258))
open(r"D:\XiuXian\_analysis\re\s45_type1hist.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
