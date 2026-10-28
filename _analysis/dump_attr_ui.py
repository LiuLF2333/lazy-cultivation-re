# -*- coding: utf-8 -*-
"""Dump the attribute-UI label region to find an existing attribute choice UI."""
import io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\attr_ui_region.txt"
raw = open(EXE, "rb").read()


def dump(a, b, label, f):
    f.write("\n===== %s  0x%X-0x%X =====\n" % (label, a, b))
    i = a
    while i < b - 1:
        j = i
        ch = []
        while j + 1 < b:
            cp = raw[j] | (raw[j + 1] << 8)
            if cp == 0:
                break
            if (0x4E00 <= cp <= 0x9FFF) or (0x20 <= cp <= 0x7E) or (0x3000 <= cp <= 0x303F) \
               or (0xFF00 <= cp <= 0xFFEF) or cp in (0x2018, 0x2019, 0x201C, 0x201D, 0x2026, 0x00B7):
                ch.append(cp)
                j += 2
            else:
                break
        if len(ch) >= 2:
            s = bytes(x for cp in ch for x in (cp & 0xFF, cp >> 8)).decode("utf-16-le", errors="replace")
            f.write("  0x%06X  %s\n" % (i, s))
            i = j
        else:
            i += 2


f = io.StringIO()
dump(0x28ED00, 0x28F100, "attribute UI labels (根骨[/机缘[ region)", f)
dump(0x28B200, 0x28B400, "attribute-related (灵根 growth)", f)
dump(0x2BC200, 0x2BC500, "help text about attributes", f)
open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
