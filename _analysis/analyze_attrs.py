# -*- coding: utf-8 -*-
"""Deep analysis of attribute-related items and tables."""
import os, io

D = r"D:\XiuXian\_analysis\decoded"
OUT = r"D:\XiuXian\_analysis\reports"
os.makedirs(OUT, exist_ok=True)

def lines(name):
    t = open(os.path.join(D, name + ".txt"), encoding="utf-8").read()
    return [l for l in t.replace("\r\n", "\n").replace("\r", "\n").split("\n") if l.strip()]

w = io.StringIO()

# 1) GameAttribStringTable
w.write("========== GameAttribStringTable ==========\n")
for l in lines("GameAttribStringTable"):
    w.write(l + "\n")

# 2) All items with attribute-ish descriptions
w.write("\n\n========== ItemTable rows mentioning attribute keywords ==========\n")
KW = ["根骨", "机缘", "悟性", "资质", "灵根", "属性", "随机", "洗髓", "易经", "脱胎"]
it = lines("ItemTable")
w.write(it[0] + "\n")
for l in it[1:]:
    f = l.split(",")
    if any(k in l for k in KW):
        w.write(l + "\n")

# 3) All items grouped by type1, full listing for 120..140
w.write("\n\n========== ItemTable rows with type1 in 120..140 ==========\n")
w.write(it[0] + "\n")
for l in it[1:]:
    f = l.split(",")
    if len(f) < 18:
        continue
    try:
        t1 = int(f[13])
    except ValueError:
        continue
    if 120 <= t1 <= 140:
        w.write(l + "\n")

# 4) search every decoded table for 随机
w.write("\n\n========== '随机' occurrences across all tables ==========\n")
for name in sorted(os.listdir(D)):
    if not name.endswith(".txt"):
        continue
    for i, l in enumerate(lines(name[:-4]), 1):
        if "随机" in l:
            w.write(f"[{name[:-4]}:{i}] {l}\n")

open(os.path.join(OUT, "attr_analysis.txt"), "w", encoding="utf-8").write(w.getvalue())
print("ok")
