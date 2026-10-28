# -*- coding: utf-8 -*-
"""Find function-pointer tables (runs of dwords all pointing into .text),
which is how a data-driven type1 dispatch would be encoded."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\fptables.txt"
f = io.StringIO()
trp, tva, trs = pe.text()
TEXT_LO, TEXT_HI = IMAGE_BASE + tva, IMAGE_BASE + tva + trs

f.write("### .text range 0x%X..0x%X\n" % (TEXT_LO, TEXT_HI))

runs = []
for s in pe.sections:
    if s["name"] in (".reloc",):
        continue
    base = s["rawptr"]
    n = s["rawsize"] // 4
    i = 0
    while i < n:
        off = base + i * 4
        v = struct.unpack_from("<I", pe.raw, off)[0]
        if TEXT_LO <= v < TEXT_HI:
            j = i
            while j < n:
                vv = struct.unpack_from("<I", pe.raw, base + j * 4)[0]
                if TEXT_LO <= vv < TEXT_HI:
                    j += 1
                else:
                    break
            if j - i >= 8:
                va = IMAGE_BASE + s["va"] + (i * 4 - (base - s["rawptr"]))
                va = pe.off2va(base + i * 4)
                runs.append((va, j - i, s["name"], base + i * 4))
            i = j
        else:
            i += 1

runs.sort(key=lambda x: -x[1])
f.write("\n### runs of >=8 consecutive .text pointers: %d\n" % len(runs))
for va, ln, sec, off in runs:
    f.write("  section %-7s VA 0x%08X  len %3d  file 0x%X\n" % (sec, va, ln, off))

f.write("\n\n### full dump of the runs with length 15..60 (dispatch-table candidates)\n")
for va, ln, sec, off in runs:
    if 15 <= ln <= 60:
        f.write("\n*** VA 0x%08X len %d (%s)\n" % (va, ln, sec))
        for k in range(ln):
            v = struct.unpack_from("<I", pe.raw, off + k * 4)[0]
            f.write("    [%2d] type1=%3d -> 0x%08X\n" % (k, 100 + k, v))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok runs=%d" % len(runs))
