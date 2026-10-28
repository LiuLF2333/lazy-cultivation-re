# -*- coding: utf-8 -*-
"""Decisive: what are 0x4216B0 / 0x421730 / 0x40A620->0x40AA40->0x40A6F0?
And what is 0x40A110? Do they reach a modal dialog API?"""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\chooser_roles.txt"
f = io.StringIO()

for start, n, label in [
    (0x4216B0, 0x80, "0x4216B0 ctor/title"),
    (0x421730, 0xA0, "0x421730 add-entry"),
    (0x40AA40, 0x80, "0x40AA40 (called by 0x40A600)"),
    (0x40A6F0, 0x90, "0x40A6F0 (tail of 0x40A600)"),
    (0x40A110, 0x80, "0x40A110"),
    (0x40A180, 0x60, "0x40A180"),
]:
    f.write("\n" + "=" * 74 + "\n### %s\n" % label + "=" * 74 + "\n")
    for ins in disasm(pe, start, n):
        f.write(fmt(ins) + "\n")

# Which imports are modal-dialog-related?
f.write("\n\n### modal-dialog-ish import usage\n")
import struct
# walk import descriptors
pe_off = 0x3C
opt = pe.pe_off + 24
dd = opt + 96  # data directory start for PE32
imp_rva, imp_sz = struct.unpack_from("<II", pe.raw, dd + 8 * 1)
f.write("  Import dir RVA 0x%X size 0x%X\n" % (imp_rva, imp_sz))
o = pe.va2off(0x400000 + imp_rva)
while True:
    oft, tds, fc, name_rva, fta = struct.unpack_from("<IIIII", pe.raw, o)
    if name_rva == 0 and fta == 0:
        break
    nm = pe.cstr(0x400000 + name_rva, 40)
    f.write("  DLL %s\n" % nm)
    o += 20

# Find call sites of DialogBoxParamW / MessageBoxW etc via IAT pointers
f.write("\n### IAT slots referenced and their names (interesting ones)\n")
o = pe.va2off(0x400000 + imp_rva)
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
            if any(k in fn.lower() for k in ("dialog", "modal", "messagebox", "listbox", "combobox")):
                # find the IAT slot VA
                slot_va = 0x400000 + fta + (to - pe.va2off(0x400000 + thunk))
                f.write("  %-22s %-28s IAT VA 0x%X\n" % (dll, fn, slot_va))
        to += 4
    o += 20

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
