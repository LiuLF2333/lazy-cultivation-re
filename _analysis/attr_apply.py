# -*- coding: utf-8 -*-
"""Find the code that APPLIES attribute increases, via the message
'福星高照，%s提高了%d点.' (0x680B44) and related attribute-gain strings.
Also check whether a popup-menu based chooser is feasible from the imports."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\attr_apply.txt"
f = io.StringIO()

def xrefs(va):
    b = struct.pack("<I", va)
    out = []
    st = 0
    while True:
        j = pe.raw.find(b, st)
        if j < 0:
            break
        out.append(pe.off2va(j))
        st = j + 1
    return out

# strings of interest
cands = {}
for va in (0x680B44, 0x680B68, 0x680AE8, 0x680A70):
    cands[va] = pe.wide(va, 200)
f.write("### attribute-gain message strings and their xrefs\n")
for va, s in cands.items():
    f.write("\n--- 0x%X %r\n" % (va, s))
    for x in xrefs(va):
        if x is None:
            continue
        f.write("    ref at VA 0x%X\n" % x)

# Where is the 福星高照 message used?
f.write("\n\n### disassembly around each 0x680B44 xref\n")
for x in xrefs(0x680B44):
    if x is None or not (0x401000 <= x < 0x644800):
        continue
    f.write("\n===== xref 0x%X\n" % x)
    for ins in disasm(pe, x - 0xA0, 0x140):
        f.write(fmt(ins) + "\n")

# menu APIs in imports?
f.write("\n\n### import names containing menu/window/track\n")
opt = pe.pe_off + 24
dd = opt + 96
imp_rva, imp_sz = struct.unpack_from("<II", pe.raw, dd + 8)
o = pe.va2off(0x400000 + imp_rva)
allfns = []
while True:
    oft, tds, fc, name_rva, fta = struct.unpack_from("<IIIII", pe.raw, o)
    if name_rva == 0 and fta == 0:
        break
    dll = pe.cstr(0x400000 + name_rva, 40)
    thunk = oft if oft else fta
    to = pe.va2off(0x400000 + thunk)
    while True:
        v = struct.unpack_from("<I", pe.raw, to)[0]
        if v == 0:
            break
        if not (v & 0x80000000):
            fn = pe.cstr(0x400000 + v + 2, 60)
            allfns.append((dll, fn))
        to += 4
    o += 20
for dll, fn in allfns:
    lf = fn.lower()
    if any(k in lf for k in ("menu", "track", "window", "getcursor", "loadlibrary", "getprocaddress",
                             "createpopup", "getforegroundwindow", "getactivewindow", "setforegroundwindow")):
        f.write("  %-16s %s\n" % (dll, fn))
f.write("\n  total imports: %d\n" % len(allfns))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
