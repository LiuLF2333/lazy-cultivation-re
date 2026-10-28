# -*- coding: utf-8 -*-
"""Examine the strongest type1-dispatcher candidate at 0x42B800."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\cand_42b800.txt"
f = io.StringIO()

for start, n, label in [(0x42B7C0, 0x140, "candidate A 0x42B83F/0x42B862"),
                        (0x49F880, 0x120, "candidate B 0x49F8CF"),
                        (0x4A0E60, 0x120, "candidate C 0x4A0ECE")]:
    f.write("\n" + "=" * 78 + "\n### %s\n" % label + "=" * 78 + "\n")
    for ins in disasm(pe, start, n):
        f.write(fmt(ins) + "\n")

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
