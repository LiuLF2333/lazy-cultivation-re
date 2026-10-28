# -*- coding: utf-8 -*-
"""Analyze ItemTable for use-effects that grant random attributes."""
import os, csv, io

D = r"D:\XiuXian\_analysis\decoded"
OUT = r"D:\XiuXian\_analysis\reports"
os.makedirs(OUT, exist_ok=True)

def rows(name):
    t = open(os.path.join(D, name + ".txt"), encoding="utf-8").read()
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    return [l for l in t.split("\n") if l.strip()]

it = rows("ItemTable")
hdr = it[0].split(",")
w = io.StringIO()
w.write("ItemTable header columns (%d):\n" % len(hdr))
for i, h in enumerate(hdr):
    w.write("  [%d] %s\n" % (i, h))
w.write("\nTotal data rows: %d\n" % (len(it) - 1))

# collect distinct type1/type2 values and their descriptions
from collections import defaultdict
t1 = defaultdict(list)
t2 = defaultdict(list)
for line in it[1:]:
    f = line.split(",")
    if len(f) < len(hdr):
        continue
    try:
        iid = f[0]
        v1 = f[13]
        n1 = f[14]
        v2 = f[15]
        n2 = f[16]
        desc = f[17] if len(f) > 17 else ""
    except Exception:
        continue
    t1[v1].append((iid, n1, desc))
    if v2 not in ("0", ""):
        t2[v2].append((iid, n2, desc))

w.write("\n=== type1 -> count (top 40) ===\n")
for k, v in sorted(t1.items(), key=lambda x: -len(x[1]))[:40]:
    w.write("  type1=%-8s count=%-4d e.g. desc=%s\n" % (k, len(v), v[0][2][:40]))

w.write("\n=== type2 (non-zero) -> count ===\n")
for k, v in sorted(t2.items(), key=lambda x: -len(x[1]))[:40]:
    w.write("  type2=%-8s count=%-4d e.g. desc=%s\n" % (k, len(v), v[0][2][:40]))

w.write("\n=== items whose description mentions 随机 ===\n")
for line in it[1:]:
    if "随机" in line:
        w.write("  " + line + "\n")

w.write("\n=== items whose description mentions 属性 ===\n")
for line in it[1:]:
    if "属性" in line:
        w.write("  " + line + "\n")

open(os.path.join(OUT, "itemtable_analysis.txt"), "w", encoding="utf-8").write(w.getvalue())
print("written")
