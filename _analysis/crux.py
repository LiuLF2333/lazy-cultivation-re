# -*- coding: utf-8 -*-
"""CRUX: determine what `call 0x40A620` returns.
0x40A600: call 0x40AA40 -> eax; then ecx=eax; call 0x40A6F0; ret  (no eax set!)
=> eax after 0x40A6F0 is the return value. Verify 0x40A6F0 + 0x40AA40,
and find a call site that CONSUMES eax right after call 0x40A620."""
import io, re, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\crux.txt"
f = io.StringIO()

for start, n, label in [
    (0x40AA40, 0x120, "0x40AA40 (invoked by 0x40A600, result->eax)"),
    (0x40A6F0, 0x120, "0x40A6F0 (final call of 0x40A600; eax is the retval)"),
    (0x40A200, 0x60, "0x40A200 (title setter?)"),
    (0x40A260, 0x60, "0x40A260"),
    (0x40A290, 0x60, "0x40A290"),
]:
    f.write("\n" + "=" * 74 + "\n### %s\n" % label + "=" * 74 + "\n")
    for ins in disasm(pe, start, n):
        f.write(fmt(ins) + "\n")

# find every call 0x40A620 and show the 12 instructions after it
cs = pe.find_calls_to(0x40A620)
f.write("\n\n### %d call sites of 0x40A620; showing what happens right after\n" % len(cs))
consume = 0
for c in cs:
    after = list(disasm(pe, c, 0x40))
    # does eax get used before being clobbered?
    lines = []
    used = False
    for a, b, m, o in after[1:]:
        lines.append("      0x%08X %-12s %s" % (a, m, o))
        if re.search(r"\beax\b", o) or m in ("test", "cmp") and o.startswith("eax"):
            used = True
            break
        if m == "call":
            break
    if used:
        consume += 1
        f.write("\n--- 0x%08X CONSUMES eax:\n" % c)
        f.write("\n".join(lines[:8]) + "\n")
f.write("\n### sites consuming eax: %d / %d\n" % (consume, len(cs)))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok calls=%d consume=%d" % (len(cs), consume))
