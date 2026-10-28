# -*- coding: utf-8 -*-
import sys, io, csv
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

W("### GameAttribStringTable decoded ###")
rows = list(csv.reader(io.open(r"D:\XiuXian\_analysis\decoded\GameAttribStringTable.txt", encoding="utf-8")))
for i, r in enumerate(rows[:70]):
    W("  %3d: %s" % (i, " | ".join(r)))
W("")
W("### rows whose 内ID (col1) in 100..118 or 200..204 or 1..6 ###")
for r in rows[1:]:
    if len(r) < 2: continue
    try: nid = int(r[1])
    except Exception: continue
    if 100 <= nid <= 118 or 200 <= nid <= 204 or 1 <= nid <= 6 or nid in (104,105,106,107,108):
        W("  内ID=%4d  %s" % (nid, " | ".join(r[1:6])))
open(r"D:\XiuXian\_analysis\re\s57_attrtab.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
