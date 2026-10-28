# -*- coding: utf-8 -*-
"""Find the real type1 use-dispatcher: sweep all .text for cmp/sub with
immediates in the type1 range (100..135) and cluster the hits."""
import io, re, sys
from collections import defaultdict
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt, _md

pe = PE()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]
OUT = r"D:\XiuXian\_analysis\reports\type1_dispatch.txt"
f = io.StringIO()

hits = []
pos = 0
while pos < len(text):
    got = list(_md.disasm(text[pos:pos + 15], IMAGE_BASE + tva + pos, count=1))
    if not got:
        pos += 1
        continue
    i = got[0]
    m, o = i.mnemonic, i.op_str
    if m in ("cmp", "sub", "mov") and re.search(r", (0x[0-9a-f]{2,3})$", o):
        imm = int(o.rsplit(", ", 1)[1], 16)
        if 99 <= imm <= 135 and ("[" not in o.split(",")[0] or True):
            hits.append((i.address, m, o, imm))
    pos += i.size

f.write("### all cmp/sub/mov with imm 99..135 in .text: %d hits\n" % len(hits))
byimm = defaultdict(list)
for va, m, o, imm in hits:
    byimm[imm].append(va)

for imm in sorted(byimm):
    f.write("  imm %3d (0x%02X): %d sites\n" % (imm, imm, len(byimm[imm])))

# cluster: find dense windows = the dispatcher
f.write("\n### dense windows (>=6 distinct type1 values within 0x600 bytes)\n")
addrs = sorted(set(va for va, _, _, _ in hits))
i = 0
clusters = []
while i < len(addrs):
    j = i
    while j + 1 < len(addrs) and addrs[j + 1] - addrs[i] <= 0x600:
        j += 1
    win = [a for a in addrs[i:j + 1]]
    vals = sorted(set(imm for va, m, o, imm in hits if va in win))
    if len(win) >= 6:
        clusters.append((win[0], win[-1], win, vals))
        i = j + 1
    else:
        i += 1

for a, b, win, vals in clusters:
    f.write("\n  window 0x%08X..0x%08X  (%d sites)\n" % (a, b, len(win)))
    f.write("    type1 values: %s\n" % vals)
    if 110 in vals or 132 in vals:
        f.write("    *** CONTAINS 110 or 132 ***\n")

# focus: windows containing 110
f.write("\n\n### windows containing type1 == 110\n")
for a, b, win, vals in clusters:
    if 110 in vals:
        f.write("\n  window 0x%08X..0x%08X vals=%s\n" % (a, b, vals))
        for va, m, o, imm in hits:
            if a <= va <= b:
                f.write("    0x%08X  %s %s\n" % (va, m, o))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok, clusters=%d" % len(clusters))
