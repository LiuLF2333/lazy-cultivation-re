# -*- coding: utf-8 -*-
"""Full UTF-16LE CJK string extraction from the EXE, searching for UI/dialog text."""
import io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\utf16_cjk_all.txt"
raw = open(EXE, "rb").read()

strings = []
i = 0
n = len(raw)
while i + 1 < n:
    j = i
    ch = []
    while j + 1 < n:
        cp = raw[j] | (raw[j + 1] << 8)
        if cp == 0:
            break
        # accept CJK, ASCII printable, and common CJK punctuation
        if (0x4E00 <= cp <= 0x9FFF) or (0x20 <= cp <= 0x7E) or (0x3000 <= cp <= 0x303F) \
           or (0xFF00 <= cp <= 0xFFEF) or cp in (0x2018, 0x2019, 0x201C, 0x201D, 0x2026):
            ch.append(cp)
            j += 2
        else:
            break
    if len(ch) >= 2:
        try:
            s = bytes(x for cp in ch for x in (cp & 0xFF, cp >> 8)).decode("utf-16-le")
        except Exception:
            s = None
        if s and any(0x4E00 <= ord(c) <= 0x9FFF for c in s):
            strings.append((i, s))
        i = j if j > i else i + 2
    else:
        i += 2

# dedupe preserving order
seen = set()
uniq = []
for off, s in strings:
    if s not in seen:
        seen.add(s)
        uniq.append((off, s))

KEYS = ["选择", "属性", "根骨", "机缘", "悟性", "确定", "取消", "随机",
        "使用", "分配", "点数", "灵根", "洗髓", "易经", "提升", "增加",
        "请选择", "遗忘", "技能", "弹出", "提示", "是否"]

f = io.StringIO()
f.write("Total distinct UTF-16LE strings containing CJK: %d\n" % len(uniq))
f.write("\n")
for k in KEYS:
    hits = [(o, s) for o, s in uniq if k in s and len(s) < 90]
    f.write("\n===== '%s'  (%d hits) =====\n" % (k, len(hits)))
    for o, s in hits[:80]:
        f.write("  0x%06X  %s\n" % (o, s))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("distinct CJK wide strings:", len(uniq))
