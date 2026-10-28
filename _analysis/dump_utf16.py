# -*- coding: utf-8 -*-
"""Dump UTF-16LE string regions that describe data/MOD loading paths."""
import re, io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\utf16_regions.txt"
raw = open(EXE, "rb").read()


def dump_utf16(a, b, label, f):
    f.write("\n===== %s  0x%X-0x%X =====\n" % (label, a, b))
    data = raw[a:b]
    # UTF-16LE runs of printable/wide chars
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00|[\x00-\xff][\x00-\x9f]){3,}", data):
        try:
            t = m.group().decode("utf-16-le", errors="strict")
        except Exception:
            continue
        if not t.strip():
            continue
        if any(ord(c) < 32 for c in t):
            continue
        f.write("  0x%X  %s\n" % (a + m.start(), t))


f = io.StringIO()
dump_utf16(0x280c80, 0x280f00, "Data/.gjd path region A", f)
dump_utf16(0x281a00, 0x281f00, ".gjd path region B", f)
dump_utf16(0x28e900, 0x28ed00, "config/Mod/SelMod region", f)
dump_utf16(0x290f00, 0x291500, "Mods region", f)
dump_utf16(0x289f00, 0x28a100, "Save/RoleData region", f)
dump_utf16(0x285c80, 0x285e80, "config.ini region", f)

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
