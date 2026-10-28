# -*- coding: utf-8 -*-
"""Extract the type1=114 handler (existing 'use item -> modal chooser' template),
confirm the desc-builder jump table, and find attribute-apply helpers."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\handler_114.txt"
f = io.StringIO()

f.write("#" * 78 + "\n")
f.write("# type1=114 handler region (use item -> choose pet skill to forget)\n")
f.write("# template string '选择让[%%s]遗忘以下其中一个技能：' pushed at VA 0x408225\n")
f.write("#" * 78 + "\n")
for ins in disasm(pe, 0x408100, 0x300):
    f.write(fmt(ins) + "\n")

f.write("\n\n" + "#" * 78 + "\n")
f.write("# '选择携带的物品：' chooser (VA 0x68E9CC push at 0x4A00D4) - 2nd reference\n")
f.write("#" * 78 + "\n")
for ins in disasm(pe, 0x4A0060, 0x120):
    f.write(fmt(ins) + "\n")

f.write("\n\n" + "#" * 78 + "\n")
f.write("# '选择派遣的宠物：' chooser (push 0x68E960 at 0x49FE76)\n")
f.write("#" * 78 + "\n")
for ins in disasm(pe, 0x49FE10, 0x120):
    f.write(fmt(ins) + "\n")

# ---- confirm desc builder jump table at 0x418CA8 ----
f.write("\n\n" + "#" * 78 + "\n# desc-builder jump table VA 0x418CA8 (base type1=100)\n" + "#" * 78 + "\n")
for k in range(40):
    v = pe.u32(0x418CA8 + k * 4)
    f.write("  [%2d] type1=%3d -> 0x%08X\n" % (k, 100 + k, v if v else 0))

# ---- callers of the attribute lookup 0x426240 ----
f.write("\n\n" + "#" * 78 + "\n# callers of attribute lookup 0x426240\n" + "#" * 78 + "\n")
cs = pe.find_calls_to(0x426240)
f.write("  %d sites: %s\n" % (len(cs), [hex(c) for c in cs]))

# ---- the desc-builder function head, to find how type1 is fetched ----
f.write("\n\n" + "#" * 78 + "\n# desc builder 0x418400 head (how it reads type1)\n" + "#" * 78 + "\n")
for ins in disasm(pe, 0x418400, 0x120):
    f.write(fmt(ins) + "\n")

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
