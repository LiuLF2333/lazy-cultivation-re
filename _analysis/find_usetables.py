# -*- coding: utf-8 -*-
"""Find real jump tables in .text and identify those indexed by type1 (base 100)."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\jumptables.txt"
f = io.StringIO()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]


def is_code(va):
    return 0x401000 <= va < 0x401000 + trs


# jmp dword ptr [reg*4 + disp32]  ==  FF 24 <sib> disp32, sib&0xC7 == 0x85
sites = []
i = 0
while i < len(text) - 7:
    if text[i] == 0xFF and text[i + 1] == 0x24 and (text[i + 2] & 0xC7) == 0x85:
        disp = struct.unpack_from("<I", text, i + 3)[0]
        sites.append((IMAGE_BASE + tva + i, disp))
        i += 7
    else:
        i += 1

f.write("### jmp [reg*4+disp32] sites: %d\n" % len(sites))
good = []
for site, disp in sites:
    n = 0
    while n < 300:
        v = pe.u32(disp + n * 4)
        if v is None or not is_code(v):
            break
        n += 1
    if n >= 4:
        good.append((site, disp, n))
good.sort(key=lambda x: -x[2])
f.write("### validated tables (>=4 code entries): %d\n" % len(good))
for site, disp, n in good:
    f.write("  site 0x%08X -> table 0x%08X  entries %3d\n" % (site, disp, n))

f.write("\n### index-base analysis: context before each site\n")
for site, disp, n in good:
    f.write("\n--- site 0x%08X table 0x%08X entries %d\n" % (site, disp, n))
    ctx = list(disasm(pe, site - 0x40, 0x40))
    for x in ctx:
        f.write("    %s\n" % fmt(x))

f.write("\n\n### tables whose entry count is 33-37 (type1 100..132 window)\n")
for site, disp, n in good:
    if 30 <= n <= 40:
        f.write("\n*** site 0x%08X table 0x%08X entries %d\n" % (site, disp, n))
        for k in range(min(n, 36)):
            f.write("     [%2d] type1=%3d -> 0x%08X\n" % (k, 100 + k, pe.u32(disp + k * 4)))

# ---- 境界点 string search ----
f.write("\n\n### '境界点' occurrences (UTF-16LE)\n")
for s in ("境界点", "基础属性", "随机基础属性"):
    b = s.encode("utf-16-le")
    st = 0
    hits = []
    while True:
        j = pe.raw.find(b, st)
        if j < 0:
            break
        va = pe.off2va(j)
        if va:
            hits.append(va)
        st = j + 1
    f.write("  %r -> %s\n" % (s, [hex(h) for h in hits]))
    for h in hits:
        f.write("     ctx: %r\n" % (pe.wide(h, 80),))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok sites=%d good=%d" % (len(sites), len(good)))
