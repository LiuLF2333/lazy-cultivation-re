# -*- coding: utf-8 -*-
"""Find the real obfuscation key by scoring against common Chinese chars."""
import os

SRC = r"D:\XiuXian\data"

COMMON = (
    "物品名称类型属性攻击防御生命法力速度价格等级数量描述效果使用获得增加减少伤害暴击命中闪避声望经验金币商店出售购买"
    "装备武器防具饰品法宝丹药材料任务奖励技能宠物怪物地图关卡境界修炼灵石草药矿石套装强化炼丹配方掉落概率品质"
    "角色玩家回合冷却持续目标范围消耗恢复提升降低最大最小当前上限基础成长值系数成功失败时间天数年月日时秒"
    "火水木金土风雷冰光暗毒治疗辅助主动被动初始需要条件限制绑定不可交易堆叠数量个只件把柄颗枚张本卷"
    "一二三四五六七八九十百千万亿零两第共有无多少大小高低前后左右上下内外"
    "了的是在和与或不没这那就都也很会能可以要将被把从到对为以于之其"
)

def score(text):
    return sum(text.count(c) for c in COMMON)

results = []
for key in range(256):
    total = 0
    for name in os.listdir(SRC):
        if name.lower().endswith(".gjd"):
            raw = open(os.path.join(SRC, name), "rb").read()
            data = bytes(b ^ key for b in raw)
            total += score(data.decode("gbk", errors="replace"))
    results.append((total, key))

results.sort(reverse=True)
print("TOP single-byte keys (score, key):")
for s, k in results[:10]:
    print(f"  0x{k:02X} ({k:3d}) -> {s}")

# also test 2-byte and 4-byte repeating keys derived from the best candidate
best_single = results[0][1]
print("\nBest single key =", hex(best_single))
