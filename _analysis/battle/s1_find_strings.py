# -*- coding: utf-8 -*-
"""Locate battle-related strings and their code cross-references."""
import sys, struct, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p = PE(r"D:\XiuXian\懒人修仙传.exe")
d = p.raw
TEXT = next(s for s in p.sections if s["name"] == ".text")
TS, TE = TEXT["rawptr"], TEXT["rawptr"] + TEXT["rawsize"]

md = Cs(CS_ARCH_X86, CS_MODE_32)

def read_utf16(off, maxlen=200):
    out = []
    for i in range(off, min(off + maxlen * 2, len(d)), 2):
        cp = d[i] | (d[i + 1] << 8)
        if cp == 0:
            break
        out.append(chr(cp))
    return "".join(out)

# 1) collect all UTF-16 strings with VA
strs = {}
for s in p.sections:
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    i = a
    while i < b - 3:
        cp = d[i] | (d[i + 1] << 8)
        if cp and ((0x20 <= cp < 0x7f) or (0x4e00 <= cp <= 0x9fff) or (0x3000 <= cp <= 0x303f)
                   or (0xff00 <= cp <= 0xffef) or cp in (0x2026, 0x2014, 0x2018, 0x2019, 0x201c, 0x201d, 0x2103, 0xb7)):
            # try to read a whole string
            j = i
            chars = []
            ok = True
            while j + 1 < b:
                c = d[j] | (d[j + 1] << 8)
                if c == 0:
                    break
                if (0x20 <= c < 0x7f) or (0x4e00 <= c <= 0x9fff) or (0x3000 <= c <= 0x303f) or (0xff00 <= c <= 0xffef) \
                        or c in (0x2026, 0x2014, 0x2018, 0x2019, 0x201c, 0x201d, 0x2103, 0xb7):
                    chars.append(chr(c)); j += 2
                else:
                    ok = False; break
            if ok and len(chars) >= 2 and j + 1 < b and d[j] == 0 and d[j + 1] == 0:
                rva = p.va2off and None
                va = p.off2va(i)
                if va is not None:
                    strs.setdefault(va, "".join(chars))
                i = j + 2
                continue
        i += 2

print("indexed", len(strs), "utf16 strings")

KEY = ["回合", "调息", "战斗", "总战斗", "超出"]
hits = [(va, t) for va, t in strs.items() if any(k in t for k in KEY)]
for va, t in sorted(hits):
    print("STR 0x%08X off=0x%06X %s" % (va, p.va2off(va) or 0, t))

# 2) find dword references in .text
xref = {}
i = TS
while i < TE - 4:
    v = struct.unpack_from("<I", d, i)[0]
    if v in strs:
        prev = d[i - 1] if i > TS else 0
        kind = "push" if prev == 0x68 else ("mov" if 0xB8 <= prev <= 0xBF else "dword")
        xref.setdefault(v, []).append((i - 1 if prev in (0x68,) or 0xB8 <= prev <= 0xBF else i, kind))
    i += 1

print("\n=== xrefs ===")
for va, t in sorted(hits):
    sites = xref.get(va, [])
    print("0x%08X %-30s sites=%d" % (va, t[:28], len(sites)))
    for off, kind in sites[:12]:
        sva = p.off2va(off)
        print("    %s at file 0x%06X va 0x%08X" % (kind, off, sva or 0))
