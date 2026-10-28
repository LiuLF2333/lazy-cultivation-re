# -*- coding: utf-8 -*-
import struct, sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
raw = pe.raw
out = io.StringIO()

imp_rva, imp_sz = struct.unpack_from("<II", raw, pe.opt + 96 + 8 * 1)
imp_off = pe.va2off(IMAGE_BASE + imp_rva)
i = imp_off
entries = []
while True:
    oft, ts, fc, nameRVA, firstThunk = struct.unpack_from("<IIIII", raw, i)
    if nameRVA == 0:
        break
    dll = raw[pe.va2off(IMAGE_BASE + nameRVA):].split(b"\x00")[0].decode("latin1")
    thunk = pe.va2off(IMAGE_BASE + firstThunk)
    j = thunk
    while True:
        ent = struct.unpack_from("<I", raw, j)[0]
        if ent == 0:
            break
        slot = IMAGE_BASE + firstThunk + (j - thunk)
        if ent & 0x80000000:
            fn = "ord#%d" % (ent & 0xffff)
        else:
            no = pe.va2off(IMAGE_BASE + ent)
            fn = raw[no + 2:].split(b"\x00")[0].decode("latin1")
        entries.append((dll, fn, slot))
        j += 4
    i += 20

print("total imports:", len(entries), file=out)
for dll, fn, slot in sorted(entries):
    print("  %-16s %-30s 0x%08X" % (dll, fn, slot), file=out)

open(r"D:\XiuXian\_analysis\reports\imports_all.txt", "w", encoding="utf-8").write(out.getvalue())
print("ok", len(entries))
