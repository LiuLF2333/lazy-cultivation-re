# -*- coding: utf-8 -*-
"""Dump the tooltip-builder head (before 0x418400) to learn how the
jump-table index and the value field are read from the item record."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\tooltip_head.txt"
f = io.StringIO()

f.write("### tooltip builder head, VA 0x418300..0x418410\n")
for ins in disasm(pe, 0x418300, 0x110):
    f.write(fmt(ins) + "\n")

f.write("\n### type1=110 branch VA 0x4185C5 and type1=132 branch VA 0x4185E5\n")
for ins in disasm(pe, 0x4185A0, 0xA0):
    f.write(fmt(ins) + "\n")

# decode the strings referenced by the 110/132 branches
f.write("\n### strings in the 110/132 tooltip area\n")
for va in (0x6814C4, 0x6815C4, 0x681348, 0x6812B0, 0x6812CC):
    f.write("  0x%X %r\n" % (va, pe.wide(va)))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
