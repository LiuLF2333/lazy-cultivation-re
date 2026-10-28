# -*- coding: utf-8 -*-
"""List every site in .text that compares/ranges against 110 or 132, with
enough surrounding context to distinguish a use-dispatcher from noise."""
import io, re, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt, _md

pe = PE()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]
OUT = r"D:\XiuXian\_analysis\reports\sites_110_132.txt"
f = io.StringIO()

# collect decoded instruction boundaries from a linear sweep, then pick hits
insns = []
pos = 0
while pos < len(text):
    got = list(_md.disasm(text[pos:pos + 15], IMAGE_BASE + tva + pos, count=1))
    if not got:
        pos += 1
        continue
    i = got[0]
    insns.append((i.address, i.mnemonic, i.op_str, i.size))
    pos += i.size

f.write("### total decoded insns: %d\n" % len(insns))
idx = {a: k for k, (a, m, o, s) in enumerate(insns)}


def show(target_imm, label):
    f.write("\n\n" + "=" * 78 + "\n### sites with immediate %d (0x%02X) — %s\n" % (target_imm, target_imm, label) + "=" * 78 + "\n")
    hits = []
    for a, m, o, s in insns:
        if m not in ("cmp", "sub", "add", "mov", "push"):
            continue
        if re.search(r"(^|, )0x%x$" % target_imm, o):
            hits.append(a)
    f.write("count: %d\n" % len(hits))
    for h in hits:
        k = idx[h]
        f.write("\n--- site 0x%08X  (%s %s)\n" % (h, insns[k][1], insns[k][2]))
        for j in range(max(0, k - 12), min(len(insns), k + 10)):
            a, m, o, s = insns[j]
            mark = ">>" if a == h else "  "
            f.write("  %s 0x%08X  %-14s %s\n" % (mark, a, m, o))


show(110, "random base attribute item")
show(132, "targeted attribute item")

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
