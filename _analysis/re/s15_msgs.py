# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

NEEDLES = ["所有基础属性增加", "增加年龄随机奖励基础属性", "机缘永久增加了", "所有基础属性奖励",
           "你服用了", "最多可服用", "服用过多后将无效", "使用后立即增加使用者",
           "无法服用", "服用后使", "属性异常", "无效属性", "当前属性", "新属性", "增加了"]

for s in NEEDLES:
    b = s.encode("utf-16-le")
    st = 0; hits=[]
    while True:
        i = pe.raw.find(b, st)
        if i < 0: break
        va = pe.off2va(i)
        if va: hits.append(va)
        st = i+1
    W("%r -> %s" % (s, [hex(v) for v in hits]))
    for v in hits:
        W("     push sites: %s" % [hex(x) for x in pe.find_push_imm(v)])
        W("     dword (string-ptr) refs: %s" % [hex(x) for x in pe.find_dword_va(v)])

open(r"D:\XiuXian\_analysis\re\s15_msgs.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
