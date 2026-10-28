# -*- coding: utf-8 -*-
"""Check furnace/recipe sources for attribute pills and 从分类 semantics."""
import os, io
from collections import Counter

D = r"D:\XiuXian\_analysis\decoded"
OUT = r"D:\XiuXian\_analysis\reports"

def lines(name):
    t = open(os.path.join(D, name + ".txt"), encoding="utf-8").read()
    return [l for l in t.replace("\r\n", "\n").replace("\r", "\n").split("\n") if l.strip()]

w = io.StringIO()

w.write("===================== FurnaceTable =====================\n")
for l in lines("FurnaceTable"):
    w.write(l + "\n")

w.write("\n\n===================== MakeRecipeData =====================\n")
for l in lines("MakeRecipeData"):
    w.write(l + "\n")

w.write("\n\n===================== EquipDropQualityRate =====================\n")
for l in lines("EquipDropQualityRate"):
    w.write(l + "\n")

# 从分类 semantics across ItemTable
it = lines("ItemTable")
hdr = it[0].split(",")
i_sub = hdr.index("子分类")
i_from = hdr.index("从分类")
i_t1 = hdr.index("type1")
i_name = hdr.index("名称")

w.write("\n\n===================== 从分类 distribution =====================\n")
c = Counter()
for l in it[1:]:
    f = l.split(",")
    if len(f) <= i_from:
        continue
    c[(f[i_t1], f[i_from])] += 1
for (t1, fr), n in sorted(c.items()):
    w.write("  type1=%-5s 从分类=%-4s count=%d\n" % (t1, fr, n))

w.write("\n\n=========== all items with 从分类 != 0 ===========\n")
for l in it[1:]:
    f = l.split(",")
    if len(f) <= i_from:
        continue
    if f[i_from] not in ("0", ""):
        w.write("  ID=%s 名称=%s type1=%s 子类=%s 从类=%s value1=%s 说明=%s\n"
                % (f[0], f[1], f[i_t1], f[i_sub], f[i_from], f[14], f[17] if len(f) > 17 else ""))

# search changelog for pill names
CL = r"D:\idm下载\游戏本体1.1.11\XiuXian\更新内容.txt"
try:
    t = open(CL, "rb").read().decode("gbk", errors="replace")
    w.write("\n\n=========== changelog lines mentioning pills/attrs ===========\n")
    for ln in t.replace("\r\n", "\n").split("\n"):
        if any(k in ln for k in ["太和丸", "玄黄丹", "五气回元散", "太一灵魄丸", "混元丹",
                                  "属性药", "丹药", "加点", "分配", "洗点"]):
            w.write("  " + ln.strip() + "\n")
except Exception as e:
    w.write("changelog error: %s\n" % e)

open(os.path.join(OUT, "furnace_from.txt"), "w", encoding="utf-8").write(w.getvalue())
print("ok")
