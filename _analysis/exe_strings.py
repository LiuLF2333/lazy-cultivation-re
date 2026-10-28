# -*- coding: utf-8 -*-
"""Extract readable strings from the game EXE, both plain and XOR-obfuscated."""
import re, io, os, sys

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports"
os.makedirs(OUT, exist_ok=True)
raw = open(EXE, "rb").read()
gbk = "gbk"

def sane(t):
    """Reject strings that are mostly replacement chars / control junk."""
    if not t:
        return False
    bad = sum(1 for ch in t if ch == "\ufffd" or (ord(ch) < 32 and ch not in "\r\n\t"))
    return bad <= len(t) * 0.1

def extract(data, minlen=2):
    """Extract GBK CJK+ASCII runs."""
    out = set()
    for m in re.finditer(rb"[\x20-\x7e\xa1-\xfe]{%d,}" % minlen, data):
        try:
            t = m.group().decode(gbk, errors="replace")
        except Exception:
            continue
        if not sane(t):
            continue
        if re.search(r"[\u4e00-\u9fff]", t) or re.match(r"^[\x20-\x7e]+$", t):
            out.add(t.strip())
    return out

w = io.StringIO()

# ---- plain strings ----
plain = extract(raw, 2)
w.write("### plain strings: %d\n" % len(plain))

# ---- XOR brute force: score by Chinese relevance ----
FOCUS = ["选择", "属性", "根骨", "机缘", "悟性", "确定", "取消", "请选择",
         "使用", "随机", "分配", "点数", "道具", "物品", "灵根", "丹药",
         "洗髓", "易经", "提升", "增加", "对话框", "按钮"]
best = []
for key in range(256):
    hits = 0
    found = set()
    for name in ["Config.gjd"]:
        pass
    # score only over a chunk to keep it fast
    d = bytes(b ^ key for b in raw)
    try:
        t = d.decode(gbk, errors="replace")
    except Exception:
        continue
    for f in FOCUS:
        c = t.count(f)
        if c:
            hits += c
            found.add(f)
    best.append((hits, key, found))

best.sort(key=lambda x: -x[0])
w.write("\n### top XOR keys by FOCUS-word hits\n")
for h, k, f in best[:6]:
    w.write("  key=0x%02X hits=%d words=%s\n" % (k, h, sorted(f)[:12]))

# dump the strings for the top key
topkey = best[0][1]
if best[0][0] > 50:
    d = bytes(b ^ topkey for b in raw)
    xs = extract(d, 2)
    w.write("\n### XOR key 0x%02X strings: %d\n" % (topkey, len(xs)))

# ---- focus searches in plain strings ----
w.write("\n### plain strings containing focus words\n")
for s in sorted(plain):
    if any(f in s for f in FOCUS) and len(s) < 80:
        w.write("  " + s + "\n")

open(os.path.join(OUT, "exe_strings.txt"), "w", encoding="utf-8").write(w.getvalue())
print("plain:", len(plain), "topkey:", hex(topkey), "score:", best[0][0])
