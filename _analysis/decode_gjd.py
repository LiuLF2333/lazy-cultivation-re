# -*- coding: utf-8 -*-
"""Decode .gjd (= GBK text XOR 0x39) tables into readable dumps."""
import os, sys, re

SRC = r"D:\XiuXian\data"
OUT = r"D:\XiuXian\_analysis\decoded"
os.makedirs(OUT, exist_ok=True)

KEY = 0xC6

def decode(path, key=KEY):
    raw = open(path, "rb").read()
    data = bytes(b ^ key for b in raw)
    return data.decode("gbk", errors="replace")

for name in sorted(os.listdir(SRC)):
    if not name.lower().endswith(".gjd"):
        continue
    txt = decode(os.path.join(SRC, name))
    dst = os.path.join(OUT, name[:-4] + ".txt")
    with open(dst, "w", encoding="utf-8", newline="") as f:
        f.write(txt)
    print(f"{name}\t{len(txt)}")
print("done")
