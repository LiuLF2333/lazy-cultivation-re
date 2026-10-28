# -*- coding: utf-8 -*-
import struct, sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
raw = pe.raw
out = io.StringIO()
def p(*a): print(*a, file=out)

for s in pe.sections:
    p("  %-8s VA 0x%08X vsz 0x%08X rawptr 0x%08X rawsz 0x%08X ch 0x%08X"
      % (s["name"], IMAGE_BASE+s["va"], s["vsize"], s["rawptr"], s["rawsize"], s["chars"]))
p("  filesize 0x%X  sizeImage 0x%X" % (len(raw), struct.unpack_from("<I", raw, pe.opt+56)[0]))
p("  sectionAlign 0x%X  fileAlign 0x%X"
  % (struct.unpack_from("<I", raw, pe.opt+32)[0], struct.unpack_from("<I", raw, pe.opt+36)[0]))

# largest zero/CC runs in each section
for s in pe.sections:
    data = raw[s["rawptr"]:s["rawptr"]+s["rawsize"]]
    res = []
    for fill in (0x00, 0xCC):
        best = (0, 0)
        i = 0
        n = len(data)
        while i < n:
            if data[i] == fill:
                j = i
                while j < n and data[j] == fill:
                    j += 1
                if j - i > best[0]:
                    best = (j - i, i)
                i = j
            else:
                i += 1
        res.append(best)
    p("  %-8s  zero run %d @file 0x%X (VA 0x%X) ; CC run %d @file 0x%X (VA 0x%X)"
      % (s["name"], res[0][0], s["rawptr"]+res[0][1],
         IMAGE_BASE+s["va"]+res[0][1], res[1][0], s["rawptr"]+res[1][1],
         IMAGE_BASE+s["va"]+res[1][1]))

open(r"D:\XiuXian\_analysis\reports\layout.txt", "w", encoding="utf-8").write(out.getvalue())
print("ok")
