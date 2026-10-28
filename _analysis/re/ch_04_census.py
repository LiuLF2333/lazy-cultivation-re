# -*- coding: utf-8 -*-
"""Deep dive: 0x40Axxx + 0x4213xx helper bodies, and a census of the context
   around every call to 0x40A620 and 0x4216B0."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_04_census.txt", "w", encoding="utf-8")
def P(*a):
    OUT.write(" ".join(str(x) for x in a) + "\n")

pe = PE()

def dump(va, n, label=""):
    P("=" * 96)
    P("0x%08X  (%s)  off=0x%X" % (va, label, pe.va2off(va)))
    P("=" * 96)
    for ins in disasm(pe, va, n):
        P("   " + fmt(ins))
    P("")

for va, n, lb in [
    (0x421670, 0x60, "title setter (real)"),
    (0x421320, 0x50, "called by 0x421360 with u16 id"),
    (0x40A820, 0x90, "called by 0x40A560 / 0x40A5E0 / 0x42143E"),
    (0x40A230, 0x90, "called at sites: ecx=[ebp+8] owner"),
    (0x40A290, 0x80, "called with 15 dwords pushed from site 0x408225"),
    (0x40A260, 0x60, ""),
    (0x40A200, 0x60, ""),
    (0x40A1E0, 0x50, ""),
    (0x40A1A0, 0x60, ""),
    (0x40A180, 0x50, ""),
    (0x40A420, 0x60, ""),
    (0x40A2F0, 0x60, ""),
    (0x4219B0, 0x20, "recheck"),
]:
    dump(va, n, lb)

# ---------- census: context before each call to 0x40A620 ----------
P("#" * 100)
P("CENSUS A: instruction immediately BEFORE and AFTER each `call 0x40A620`")
P("#" * 100)

def dec_back(va, nsig):
    """Disassemble backwards: brute force find a start <= va such that
       disassembly resyncs exactly onto va, up to nsig instructions."""
    best = None
    for back in range(1, 120):
        start = va - back
        ins = list(disasm(pe, start, back + 20, resync=False))
        if not ins:
            continue
        if any(i[0] == va for i in ins):
            seq = [i for i in ins if i[0] < va]
            if best is None or len(seq) > len(best):
                best = seq
    if best is None:
        return []
    return best[-nsig:]

sites = pe.find_calls_to(0x40A620)
P("total sites: %d" % len(sites))
from collections import Counter
cnt = Counter()
examples = {}
for s in sites:
    back = dec_back(s, 3)
    key = " | ".join("%s %s" % (i[2], i[3]) for i in back)
    cnt[key] += 1
    examples.setdefault(key, []).append(s)
for k, c in cnt.most_common(25):
    P("  x%-5d %s" % (c, k))
    P("          e.g. %s" % ", ".join("0x%X" % x for x in examples[k][:6]))
OUT.close()
print("ok")
