# -*- coding: utf-8 -*-
"""For every [reg+0x278] read site, dump a window and flag nearby signals:
attribute-apply (add/mov to +0x88x), 426240 calls, RNG calls, type1 compares."""
import io, re, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, _md, IMAGE_BASE

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\site278_ctx.txt"
f = io.StringIO()
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]

sites = []
st = 0
while True:
    i = text.find(b"\x78\x02\x00\x00", st)
    if i < 0:
        break
    if i >= 2 and text[i - 2] == 0x8B and (text[i - 1] & 0xC0) == 0x80 and (text[i - 1] & 7) != 4:
        sites.append(IMAGE_BASE + tva + i - 2)
    st = i + 1

RNG = ("0x6a1a", "rand", "0x60ec78", "0x60eebd", "0x60c37b")
f.write("### %d sites reading [reg+0x278]\n" % len(sites))

for s in sites:
    insns = list(disasm(pe, s - 0x180, 0x300))
    txt = "\n".join("%s %s" % (m, o) for _, _, m, o in insns)
    flags = []
    if "0x880" in txt or "0x884" in txt or "0x888" in txt or "0x88c" in txt:
        flags.append("ATTR-880")
    if "0x426240" in txt:
        flags.append("LOOKUP-426240")
    if "0x4261d0" in txt:
        flags.append("LOOKUP-4261d0")
    if "0x64" in txt and "sub" in txt:
        flags.append("sub64")
    if any(r in txt for r in RNG):
        flags.append("rng?")
    # find the enclosing-ish compare patterns
    type1like = re.findall(r"cmp\s+\w+, 0x(6[4-9a-f]|7[0-9a-f]|8[0-7])", txt)
    if type1like:
        flags.append("cmp-type1range x%d" % len(type1like))
    f.write("\n=== 0x%08X  %s\n" % (s, ",".join(flags) if flags else "-"))
    if flags:
        for a, b, m, o in insns:
            f.write("    0x%08X  %-14s %s\n" % (a, m, o))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok sites=%d" % len(sites))
