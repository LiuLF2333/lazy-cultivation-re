# -*- coding: utf-8 -*-
"""Map the big item-use function's case dispatch: find every `push <imm>; ...
call 0x439680` (the type1-keyed value lookup) to enumerate the type1 cases and
their containing blocks."""
import io, re, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\cases.txt"
f = io.StringIO()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]

# 1) find all call sites of 0x439680, and the nearest preceding push imm
cs = pe.find_calls_to(0x439680)
f.write("### callers of 0x439680 (get type-keyed value): %d\n" % len(cs))
rows = []
for c in cs:
    ctx = list(disasm(pe, c - 0x20, 0x20))
    # last push imm before the call in the same block
    key = None
    for a, b, m, o in reversed(ctx):
        if m == "push" and re.match(r"^0x[0-9a-f]+$", o):
            v = int(o, 16)
            if 90 <= v <= 140:
                key = v
                break
    rows.append((c, key))

rows.sort(key=lambda x: (x[1] if x[1] else 0))
for c, key in rows:
    f.write("  call 0x%08X  type1-key=%s\n" % (c, key))

f.write("\n\n### all `cmp dword ptr [reg+0x290], imm` in the big function\n")
START, END = 0x476740, 0x479A00
insns = list(disasm(pe, START, END - START))
f.write("decoded %d insns\n" % len(insns))
for va, b, m, o in insns:
    if m == "cmp" and "0x290" in o:
        f.write("  0x%08X  cmp %s\n" % (va, o))

f.write("\n\n### all `cmp dword ptr [reg+0x29x]`/`+0x28x` with immediates\n")
for va, b, m, o in insns:
    if m == "cmp" and re.search(r"\+0x2[89][0-9a-f]\]", o) and re.search(r", 0x[0-9a-f]+$", o):
        f.write("  0x%08X  %s\n" % (va, o))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok calls=%d" % len(cs))
