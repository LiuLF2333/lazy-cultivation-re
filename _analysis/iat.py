# -*- coding: utf-8 -*-
"""Resolve IAT slot VAs for the Win32 APIs the injected chooser needs."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\iat.txt"
f = io.StringIO()

opt = pe.pe_off + 24
dd = opt + 96
imp_rva, imp_sz = struct.unpack_from("<II", pe.raw, dd + 8)
o = pe.va2off(IMAGE_BASE + imp_rva)
want = ("CreatePopupMenu", "AppendMenuW", "GetCursorPos", "GetForegroundWindow",
        "TrackPopupMenu", "DestroyMenu", "GetDesktopWindow", "GetActiveWindow",
        "SetForegroundWindow", "InsertMenuW", "CreateWindowExW", "GetWindowRect")
found = {}
allnames = []
while True:
    oft, tds, fc, name_rva, fta = struct.unpack_from("<IIIII", pe.raw, o)
    if name_rva == 0 and fta == 0:
        break
    dll = pe.cstr(IMAGE_BASE + name_rva, 40)
    thunk = oft if oft else fta
    to = pe.va2off(IMAGE_BASE + thunk)
    iat_off = pe.va2off(IMAGE_BASE + fta)
    k = 0
    while True:
        v = struct.unpack_from("<I", pe.raw, to)[0]
        if v == 0:
            break
        if not (v & 0x80000000):
            fn = pe.cstr(IMAGE_BASE + v + 2, 60)
            allnames.append((dll, fn))
            if fn in want:
                found[fn] = (IMAGE_BASE + fta + k * 4, dll)
        to += 4
        k += 1
    o += 20

f.write("### resolved IAT slots\n")
for k in want:
    if k in found:
        f.write("  %-22s IAT VA 0x%08X   (%s)\n" % (k, found[k][0], found[k][1]))
    else:
        f.write("  %-22s NOT FOUND\n" % k)
f.write("\n### rva deltas (IAT VA - 0x400000)\n")
for k in want:
    if k in found:
        f.write("  %-22s 0x%X\n" % (k, found[k][0] - IMAGE_BASE))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok found=%d/%d" % (len(found), len(want)))
