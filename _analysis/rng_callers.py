# -*- coding: utf-8 -*-
"""Find the caller of 0x41A120 that belongs to the type1=110 path, and the
array it passes (the six base-attribute ids + weights)."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\rng_callers.txt"
f = io.StringIO()

cs = pe.find_calls_to(0x41A120)
f.write("### callers of 0x41A120: %d\n%s\n" % (len(cs), [hex(c) for c in cs]))

for c in cs:
    f.write("\n" + "=" * 74 + "\n### caller site 0x%X\n" % c + "=" * 74 + "\n")
    for ins in disasm(pe, c - 0x60, 0x90):
        f.write(fmt(ins) + "\n")

# the specific one at 0x476FC7
f.write("\n\n### the item-use-path call at 0x476FC7 in full context\n")
for ins in disasm(pe, 0x476F00, 0x180):
    f.write(fmt(ins) + "\n")

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok callers=%d" % len(cs))
