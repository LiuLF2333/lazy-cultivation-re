# -*- coding: utf-8 -*-
"""Confirm the type1=110 random-attribute site and find the routing to it."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\confirm110.txt"
f = io.StringIO()

f.write("=" * 76 + "\n### 0x41A120 (suspected RNG range helper)\n" + "=" * 76 + "\n")
for ins in disasm(pe, 0x41A120, 0x80):
    f.write(fmt(ins) + "\n")

f.write("\n\n" + "=" * 76 + "\n### block before the roll: 0x476E80 .. 0x476FD0\n" + "=" * 76 + "\n")
for ins in disasm(pe, 0x476E80, 0x150):
    f.write(fmt(ins) + "\n")

f.write("\n\n" + "=" * 76 + "\n### 0x4773B7 onward (common rejoins) 0x477380..0x477480\n" + "=" * 76 + "\n")
for ins in disasm(pe, 0x477380, 0x100):
    f.write(fmt(ins) + "\n")

f.write("\n\n### callers of 0x476FA1 region / jumps into 0x476FBD\n")
# find all jmp/call targets equal to 0x476FBD or 0x476FCF
trp, tva, trs = pe.text()
import struct
for target in (0x476FBD, 0x476FC0, 0x476FCF, 0x476FA1, 0x476F80):
    cs = pe.find_calls_to(target)
    f.write("  call -> 0x%X : %s\n" % (target, [hex(c) for c in cs]))
    # rel32 jmps
    hits = []
    off = trp
    end = trp + trs
    while off < end - 5:
        if pe.raw[off] in (0xE9, 0xEB, 0x0F):
            if pe.raw[off] == 0xE9:
                rel = struct.unpack_from("<i", pe.raw, off + 1)[0]
                va = pe.off2va(off)
                if va and va + 5 + rel == target:
                    hits.append(va)
            off += 1
        else:
            off += 1
    f.write("  jmp  -> 0x%X : %s\n" % (target, [hex(h) for h in hits[:20]]))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
