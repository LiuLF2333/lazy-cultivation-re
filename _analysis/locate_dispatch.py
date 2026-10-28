# -*- coding: utf-8 -*-
"""Locate the item-use dispatcher and the type1=110 / 132 / 114 handlers
using verified VA mapping."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt, _md

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\use_dispatch.txt"
f = io.StringIO()


def find_wide(s):
    """Find all VAs of a UTF-16LE string."""
    b = s.encode("utf-16-le")
    out = []
    st = 0
    while True:
        i = pe.raw.find(b, st)
        if i < 0:
            break
        va = pe.off2va(i)
        if va:
            out.append(va)
        st = i + 1
    return out


NEEDLES = [
    "服用后立即增加使用者的随机基础属性%d点。",
    "服用后立即增加使用者%d点%s,最多可使用%d颗。",
    "选择让[%s]遗忘以下其中一个技能：",
    "选择派遣的宠物：",
    "选择携带的物品：",
    "根骨",
    "机缘",
    "随机",
    "可分配属性点数。",
]

f.write("### 1. string VAs (verified)\n")
strva = {}
for s in NEEDLES:
    vs = find_wide(s)
    strva[s] = vs
    f.write("  %-46r -> %s\n" % (s, [hex(v) for v in vs]))

f.write("\n### 2. chooser thunk verification\n")
f.write("  0x40A620: %s\n" % pe.bytes_at(0x40A620, 24).hex())
f.write("  0x40A600: %s\n" % pe.bytes_at(0x40A600, 24).hex())
f.write("  impl 0x40A600 prologue disasm:\n")
for ins in disasm(pe, 0x40A600, 0x60):
    f.write("    " + fmt(ins) + "\n")

f.write("\n### 3. call sites of chooser thunk 0x40A620 / builder 0x40A6B0 / 0x40A730\n")
for tgt in (0x40A620, 0x40A6B0, 0x40A730, 0x40A600):
    cs = pe.find_calls_to(tgt)
    f.write("  target 0x%X -> %d call sites: %s\n" % (tgt, len(cs), [hex(c) for c in cs]))

f.write("\n### 4. code that references each chooser title (push imm32)\n")
for s in ["选择派遣的宠物：", "选择携带的物品：", "选择让[%s]遗忘以下其中一个技能："]:
    for v in strva[s]:
        ps = pe.find_push_imm(v)
        f.write("  %r VA 0x%X -> push sites %s\n" % (s, v, [hex(p) for p in ps]))

f.write("\n### 5. code referencing the type1=110 / 132 tooltip strings\n")
for s in ["服用后立即增加使用者的随机基础属性%d点。",
          "服用后立即增加使用者%d点%s,最多可使用%d颗。"]:
    for v in strva[s]:
        ps = pe.find_push_imm(v)
        f.write("  %r\n    VA 0x%X -> push sites %s\n" % (s, v, [hex(p) for p in ps]))

f.write("\n### 6. the item-use function found by the RE agent (VA 0x476740)\n")
for ins in disasm(pe, 0x476740, 0x140):
    f.write("  " + fmt(ins) + "\n")

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
