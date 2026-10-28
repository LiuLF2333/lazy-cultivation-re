# -*- coding: utf-8 -*-
"""Fast, decisive: find the six base-attribute name/blob arrays and every code
reference to them, plus any {1,2,3,4,5,6} dword table (the random base attr list)."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\base_attrs.txt"
f = io.StringIO()

# 1) dump the region holding 根骨 (0x680A92) and 机缘 (0x680AB0)
f.write("### region 0x680A60 .. 0x680C20 (attribute name blob)\n")
o = pe.va2off(0x680A60)
i = o
start = 0x680A60
while i < o + 0x1C0:
    cp = struct.unpack_from("<H", pe.raw, i)[0]
    if cp == 0:
        f.write("  0x%08X  (end of string)\n" % pe.off2va(i))
        i += 2
        # skip runs of zeros
    else:
        s = pe.wide(pe.off2va(i), 60)
        f.write("  0x%08X  %r\n" % (pe.off2va(i), s))
        i += len(s.encode("utf-16-le")) + 2
        while i < len(pe.raw) and struct.unpack_from("<H", pe.raw, i)[0] == 0:
            i += 2
f.write("\n")

# 2) the other cluster: 0x685E36 area (基础属性增加20点)
f.write("### region 0x685E00 .. 0x686500 (基础属性 texts)\n")
o = pe.va2off(0x685E00)
i = o
while i < o + 0x700:
    cp = struct.unpack_from("<H", pe.raw, i)[0]
    if cp == 0:
        i += 2
        continue
    va = pe.off2va(i)
    s = pe.wide(va, 200)
    if s and len(s) > 1:
        f.write("  0x%08X  %r\n" % (va, s))
    i += max(2, (len(s) + 1) * 2 if s else 2)

# 3) dword tables {1,2,3,4,5,6}
f.write("\n### search for dword runs 1,2,3,4,5,6 and 0,1,2,3,4,5\n")
for pat, name in ((b"".join(struct.pack("<I", v) for v in range(1, 7)), "1..6"),
                  (b"".join(struct.pack("<I", v) for v in range(0, 6)), "0..5")):
    st = 0
    while True:
        j = pe.raw.find(pat, st)
        if j < 0:
            break
        va = pe.off2va(j)
        f.write("  %s at VA 0x%X (file 0x%X)\n" % (name, va or -1, j))
        st = j + 1

# 4) xrefs (push imm32) to the attribute name strings
f.write("\n### push-imm sites referencing attribute name strings\n")
for va in (0x680A92, 0x680AB0, 0x6901EC, 0x690228):
    ps = pe.find_push_imm(va)
    f.write("  0x%X -> %s\n" % (va, [hex(p) for p in ps]))

# 5) all references (as an imm32 in ANY instruction) to 0x680A92 - approximate
f.write("\n### raw occurrences of the dword 0x00680A92 anywhere (any use)\n")
b = struct.pack("<I", 0x680A92)
st = 0
while True:
    j = pe.raw.find(b, st)
    if j < 0:
        break
    f.write("  file 0x%X VA 0x%X\n" % (j, pe.off2va(j) or -1))
    st = j + 1

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
