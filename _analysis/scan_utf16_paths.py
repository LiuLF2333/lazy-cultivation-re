# -*- coding: utf-8 -*-
"""Global UTF-16LE string scan of the EXE, filtered to path/ASCII-ish content."""
import io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\utf16_paths.txt"
raw = open(EXE, "rb").read()

results = []
i = 0
n = len(raw)
while i + 1 < n:
    # a UTF-16LE "wide ASCII" run: lo in printable, hi == 0
    j = i
    chars = []
    while j + 1 < n and raw[j + 1] == 0 and 0x20 <= raw[j] <= 0x7E:
        chars.append(chr(raw[j]))
        j += 2
    if len(chars) >= 3:
        results.append((i, "".join(chars)))
        i = j
    else:
        i += 1

# keep path/config-relevant ones
KEYS = ["Mod", "Data", "Res", "Save", "Role", "gjd", ".ini", ".dat", "\\", "/",
        "SelMod", "config", "ModConfig", "Load"]
f = io.StringIO()
f.write("Total wide-ASCII runs >=3 chars: %d\n" % len(results))
f.write("\n--- path/config-relevant ---\n")
seen = set()
for off, s in results:
    if any(k in s for k in KEYS) and len(s) < 120:
        key = (s,)
        if key in seen:
            continue
        seen.add(key)
        f.write("  0x%06X  %s\n" % (off, s))

f.write("\n--- all wide-ASCII runs containing a backslash or known extension ---\n")
for off, s in results:
    if ("\\" in s or ".gjd" in s or ".ini" in s or ".dat" in s) and len(s) < 120:
        f.write("  0x%06X  %s\n" % (off, s))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("runs:", len(results))
