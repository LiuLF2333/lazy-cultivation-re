# -*- coding: utf-8 -*-
"""Correct UTF-16LE string scan (2-byte aligned) + push-site finder."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_15_selstrings.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE(); raw = pe.raw

def scan_utf16():
    strs = {}
    for s in pe.sections:
        a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
        i = a
        while i + 3 < b:
            cp = raw[i] | (raw[i+1] << 8)
            if cp == 0 or cp < 0x20:
                i += 2
                continue
            j = i
            ch = []
            while j + 1 < b:
                c = raw[j] | (raw[j+1] << 8)
                if c == 0:
                    break
                if c < 0x20 and c not in (0x0D, 0x0A, 0x09):
                    ch = None
                    break
                ch.append(chr(c))
                j += 2
            if ch is not None and 2 <= len(ch) <= 300 and raw[j] == 0 and raw[j+1] == 0:
                va = pe.off2va(i)
                if va:
                    strs[va] = "".join(ch)
                i = j + 2
            else:
                i += 2
    return strs

strs = scan_utf16()
P("total utf16 strings: %d" % len(strs))
P("sanity 0x68E9CC -> %r" % strs.get(0x68E9CC))
P("sanity 0x67F734 -> %r" % strs.get(0x67F734))

KEYS = ["选择", "请选择", "增加的属性", "增加属性", "属性名", "遗忘", "增加"]
P("")
P("#"*100); P("STRINGS MATCHING KEYWORDS"); P("#"*100)
sel = sorted((va, t) for va, t in strs.items() if any(k in t for k in KEYS))
for va, t in sel:
    P("  0x%08X  %r" % (va, t))
P("count=%d" % len(sel))

P("")
P("#"*100); P("PUSH SITES for each matching string"); P("#"*100)
site_map = {}
for va, t in sel:
    hits = pe.find_push_imm(va)
    if hits:
        P("  0x%08X %r" % (va, t))
        for h in hits:
            P("        push @0x%08X" % h)
        site_map[va] = hits

P("")
P("#"*100); P("CALLS WITHIN 40 INSTRUCTIONS AFTER EACH PUSH SITE"); P("#"*100)
from collections import Counter
callcnt = Counter()
for va, hits in site_map.items():
    for h in hits:
        P("  ---- push 0x%08X (%r) at 0x%08X" % (va, strs[va][:40], h))
        n = 0
        for ins in disasm(pe, h, 0x120):
            P("        " + fmt(ins))
            if ins[2] == "call":
                callcnt[ins[3]] += 1
            n += 1
            if n > 30:
                break
        P("")
P("  common call targets after such pushes:")
for k, c in callcnt.most_common(25):
    P("     x%-4d %s" % (c, k))
OUT.close()
print("ok")
