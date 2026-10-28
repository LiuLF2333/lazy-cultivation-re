import re
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE

pe = PE(r"D:\XiuXian\懒人修仙传.exe.bak.20261019-193436-571623")


def v16(text):
    return text.encode("utf-16-le")


for term in ["设置", "自动", "收取", "音效", "音乐", "静音", "选项", "设置页面", "游戏设置", "窗口", "全屏"]:
    print("==", term)
    for enc in ("utf-16-le", "gbk"):
        data = term.encode(enc)
        pos = 0
        while True:
            i = pe.raw.find(data, pos)
            if i < 0:
                break
            va = pe.off2va(i)
            if va is not None:
                before = pe.raw[max(0, i - 16):i]
                after = pe.raw[i:i + 80]
                print("  %-8s VA 0x%08X file 0x%06X" % (enc, va, i))
            pos = i + 1
