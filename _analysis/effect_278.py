# -*- coding: utf-8 -*-
"""Targeted search: find effect code reading [reg+0x278] (= 从分类 / attr_id-1)
or [reg+0x294] (use counter) OUTSIDE the known tooltip function 0x4183B0+.
Also find the attribute-apply helper used by the 132 path.

Established: tooltip 0x4185E5 does attr_id = [item+0x278] + 1  -> 426240(container, attr_id, ?)
"""
import io, re, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt, _md

pe = PE()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]
OUT = r"D:\XiuXian\_analysis\reports\effect_278.txt"
f = io.StringIO()

# mov reg,[reg+0x278]  == 8B 8x/9x/Bx 78 02 00 00   (modrm mod=10 rm!=100)
pat = re.compile(rb"\x78\x02\x00\x00")
f.write("### occurrences of disp32 0x278 in .text (with preceding modrm)\n")
hits = []
st = 0
while True:
    i = text.find(b"\x78\x02\x00\x00", st)
    if i < 0:
        break
    va = IMAGE_BASE + tva + i
    if i >= 2:
        op = text[i - 2]
        modrm = text[i - 1]
        # mov r32, r/m32 with disp32: opcode 8B, modrm mod=10 (0x80..0xBF), rm != 100 (100=>sib)
        if op == 0x8B and (modrm & 0xC0) == 0x80 and (modrm & 0x07) != 4:
            reg = (modrm >> 3) & 7
            base = modrm & 7
            hits.append((va - 2, reg, base))
    st = i + 1

f.write("  mov reg,[reg+0x278] sites: %d\n" % len(hits))
for va, reg, base in hits:
    in_tooltip = 0x4183B0 <= va <= 0x418CA0
    tag = "  <== TOOLTIP(known)" if in_tooltip else "  *** effect candidate ***"
    f.write("\n--- 0x%08X  mov r%d,[r%d+0x278]%s\n" % (va, reg, base, tag))
    for ins in disasm(pe, va - 0x50, 0x80):
        f.write("    " + fmt(ins) + "\n")

# also 0x294
f.write("\n\n### occurrences of disp32 0x294 as mov reg,[reg+0x294]\n")
st = 0
while True:
    i = text.find(b"\x94\x02\x00\x00", st)
    if i < 0:
        break
    va = IMAGE_BASE + tva + i
    if i >= 2 and text[i - 2] == 0x8B and (text[i - 1] & 0xC0) == 0x80 and (text[i - 1] & 7) != 4:
        in_tooltip = 0x4183B0 <= va - 2 <= 0x418CA0
        f.write("\n--- 0x%08X %s\n" % (va - 2, "<== TOOLTIP" if in_tooltip else "*** candidate ***"))
        for ins in disasm(pe, va - 2 - 0x40, 0x70):
            f.write("    " + fmt(ins) + "\n")
    st = i + 1

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok 278-hits=%d" % len(hits))
