# -*- coding: utf-8 -*-
"""Dump the UTF-16 attribute-label region and the selection-dialog string regions."""
import io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\selection_ui.txt"
raw = open(EXE, "rb").read()


def dump(a, b, label, f, minlen=2):
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
               or (0xFF00 <= cp <= 0xFFEF):
                ch.append(cp)
                j += 2
            else:
                break
        if len(ch) >= minlen:
            s = bytes(x for cp in ch for x in (cp & 0xFF, cp >> 8)).decode("utf-16-le", errors="replace")
            f.write("  0x%06X  %s\n" % (i, s))
            i = j
        else:
            i += 2


f = io.StringIO()
dump(0x2C4B00, 0x2C5100, "attribute label region (随机/根骨/机缘)", f)
dump(0x27E200, 0x27E500, "skill-forget selection dialog", f)
dump(0x28D400, 0x28D700, "pet dispatch / item carry selection", f)
dump(0x28F300, 0x28F450, "herb infuse selection", f)
dump(0x28FF00, 0x290100, "equipment reroll selection", f)
dump(0x27FF00, 0x280200, "item use descriptions", f)

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
