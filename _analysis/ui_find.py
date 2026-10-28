import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE

pe = PE(r"D:\XiuXian\懒人修仙传.exe.bak.20261019-193436-571623")
needles = ["收取", "蛮荒", "自动", "宠物栏", "派遣", "寻宝", "开启", "关闭"]
for s in needles:
    b = s.encode("utf-16-le")
    hits = []
    st = 0
    while True:
        i = pe.raw.find(b, st)
        if i < 0:
            break
        va = pe.off2va(i)
        if va:
            hits.append(va)
        st = i + 1
    print(s, [hex(x) for x in hits][:30], len(hits))
    for va in hits[:10]:
        refs = pe.find_dword_va(va)
        print("   ", hex(va), repr(pe.wide(va, 80)), "refs", [hex(x) for x in refs][:20])
