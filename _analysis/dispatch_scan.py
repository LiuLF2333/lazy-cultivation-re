# -*- coding: utf-8 -*-
"""For every indirect jump-table site in .text, disassemble the preceding
window and report whether it looks like a `type1 - 100` dispatch."""
import io, re, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\dispatch_scan.txt"
f = io.StringIO()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]

sites = []
i = 0
while i < len(text) - 7:
    if text[i] == 0xFF and text[i + 1] == 0x24 and (text[i + 2] & 0xC7) == 0x85:
        disp = struct.unpack_from("<I", text, i + 3)[0]
        sib = text[i + 2]
        sites.append((IMAGE_BASE + tva + i, disp, sib))
        i += 7
    else:
        i += 1

f.write("### indirect jmp table sites: %d\n" % len(sites))
f.write("### looking for `sub X, 0x64` / `cmp X, 0x20` in the preceding 0x70 bytes\n\n")

for site, disp, sib in sites:
    ctx = list(disasm(pe, site - 0x70, 0x70))
    txt = "\n".join("%s %s" % (m, o) for _, _, m, o in ctx)
    interesting = ("0x64" in txt and ("sub" in txt or "cmp" in txt)) or "0x20" in txt
    # count valid code entries
    n = 0
    while n < 400:
        v = pe.u32(disp + n * 4)
        if v is None or not (0x401000 <= v < 0x644800):
            break
        n += 1
    mark = ""
    if any(("sub" == m and o.endswith(", 0x64")) or ("cmp" == m and o.endswith(", 0x20")) for _, _, m, o in ctx):
        mark = "   <<<< TYPE1-SHAPED"
    f.write("\n=== site 0x%08X  table 0x%08X  entries-in-code %d%s\n" % (site, disp, n, mark))
    for a, b, m, o in ctx:
        f.write("    0x%08X  %-14s %s\n" % (a, m, o))
    # dump the table head
    if n >= 10:
        f.write("    -- table entries:\n")
        for k in range(min(n, 40)):
            f.write("       [%2d] -> 0x%08X\n" % (k, pe.u32(disp + k * 4)))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok sites=%d" % len(sites))
