# -*- coding: utf-8 -*-
"""Full dump of ItemTable organized by type1, to locate random-attribute items."""
import os, io
from collections import defaultdict

D = r"D:\XiuXian\_analysis\decoded"
OUT = r"D:\XiuXian\_analysis\reports"

def lines(name):
    t = open(os.path.join(D, name + ".txt"), encoding="utf-8").read()
    return [l for l in t.replace("\r\n", "\n").replace("\r", "\n").split("\n") if l.strip()]

it = lines("ItemTable")
hdr = it[0].split(",")
idx = {h: i for i, h in enumerate(hdr)}

g = defaultdict(list)
for l in it[1:]:
    f = l.split(",")
    if len(f) < len(hdr):
        continue
    g[f[idx["type1"]]].append(f)

w = io.StringIO()
w.write("Header: %s\n" % hdr)
w.write("Distinct type1 count: %d\n\n" % len(g))

for t1 in sorted(g, key=lambda x: int(x) if x.isdigit() else 99999):
    rows = g[t1]
    w.write("\n########## type1=%s  (n=%d) ##########\n" % (t1, len(rows)))
    for f in rows:
        w.write("  ID=%s 名称=%s 分类=%s 子类=%s 从类=%s 品质=%s 等级=%s 条件=%s 判断=%s 条件值=%s 售价=%s 叠加=%s value1=%s type2=%s value2=%s\n"
                % (f[0], f[1], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12],
                   f[14], f[15], f[16]))
        w.write("        说明: %s\n" % (f[17] if len(f) > 17 else ""))

open(os.path.join(OUT, "itemtable_by_type.txt"), "w", encoding="utf-8").write(w.getvalue())
print("ok, type1 groups:", len(g))
