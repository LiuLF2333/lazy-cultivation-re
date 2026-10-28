# -*- coding: utf-8 -*-
"""Identify the real key by looking for known table header words."""
import os

SRC = r"D:\XiuXian\data"
WORDS = ["名称", "类型", "物品", "编号", "数量", "等级", "属性", "攻击", "防御",
         "概率", "掉落", "品质", "技能", "宠物", "地图", "效果", "价格", "描述",
         "Line", "Name", "Type", "Item", "Count", "Level", "Attr"]

def decode(raw, key):
    return bytes(b ^ key for b in raw).decode("gbk", errors="replace")

rows = []
for key in range(256):
    hits = 0
    for name in os.listdir(SRC):
        if not name.lower().endswith(".gjd"):
            continue
        t = decode(open(os.path.join(SRC, name), "rb").read(), key)
        for w in WORDS:
            hits += t.count(w)
    rows.append((hits, key))

rows.sort(reverse=True)
print("TOP keys by known-word hits:")
for h, k in rows[:8]:
    print(f"  0x{k:02X} ({k:3d}) -> {h}")

best = rows[0][1]
print(f"\n=== Config.gjd decoded with key 0x{best:02X} (first 600 chars) ===")
t = decode(open(os.path.join(SRC, "Config.gjd"), "rb").read(), best)
print(t[:600])

print(f"\n=== RandomBagOdds.gjd decoded with key 0x{best:02X} (first 600) ===")
t2 = decode(open(os.path.join(SRC, "RandomBagOdds.gjd"), "rb").read(), best)
print(t2[:600])
