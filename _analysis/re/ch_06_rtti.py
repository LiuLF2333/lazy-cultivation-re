# -*- coding: utf-8 -*-
"""Proper RTTI vtable recovery: find RTTICompleteObjectLocators, then vtables."""
import sys, struct, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_06_rtti.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE()
raw = pe.raw

def secname(va):
    s = pe.sec_of_va(va)
    return s["name"] if s else None

# name strings
names = {}
for s in pe.sections:
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    i = a
    while i < b - 8:
        if raw[i:i+4] in (b".?AV", b".?AU"):
            j = i
            ch = []
            while j < b and 0x20 <= raw[j] < 0x7f:
                ch.append(chr(raw[j])); j += 1
            if raw[j] == 0 and len(ch) > 5:
                names[pe.off2va(i)] = "".join(ch)
                i = j + 1
                continue
        i += 1
P("RTTI names: %d" % len(names))

def simplify(n):
    m = re.match(r"^\.\?A[VU](.*?)@@$", n)
    return m.group(1) if m else n

# TypeDescriptor VA = name_va - 8
td2name = {}
for nva, nm in names.items():
    td2name[nva - 8] = nm
    td2name[nva] = nm

# find RTTICompleteObjectLocators: signature==1, offset==0, pTD in .rdata
cols = {}   # col_va -> (classdescriptor_va, name)
for s in pe.sections:
    if s["name"] not in (".rdata", ".data"):
        continue
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    for i in range(a, b - 0x14, 4):
        sig, off, cd, ptd, pcd = struct.unpack_from("<IIIII", raw, i)
        if sig != 1 or off != 0:
            continue
        if ptd in td2name and 0x645000 <= ptd < 0x6D3000:
            cols[pe.off2va(i)] = (pcd, td2name[ptd])
P("COLs: %d" % len(cols))

# vtable: dword == col_va, next dword is code
vtmap = {}
for s in pe.sections:
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    for i in range(a, b - 4, 4):
        v = struct.unpack_from("<I", raw, i)[0]
        if v in cols:
            vt_va = pe.off2va(i + 4)
            if vt_va:
                vtmap[vt_va] = (cols[v][1], v)
P("vtables: %d" % len(vtmap))

def vt_of(va):
    cands = [k for k in vtmap if k <= va and va - k < 0x600]
    if not cands:
        return None
    k = max(cands)
    return (k, vtmap[k][0], va - k)

P("")
P("Lookups:")
for va in (0x693014, 0x6930A0, 0x693000, 0x68E900):
    P("  0x%08X -> %s" % (va, vt_of(va)))

P("")
P("#" * 100)
P("ALL VTABLE -> CLASS")
P("#" * 100)
for k in sorted(vtmap):
    P("   0x%08X  %s" % (k, vtmap[k][0]))

P("")
P("#" * 100)
P("Classes whose name contains dialog/list/select-ish words")
P("#" * 100)
KEY = ("Dlg", "Dialog", "List", "Select", "Choose", "Combo", "Choice", "Menu", "Pick")
for k in sorted(vtmap):
    nm = vtmap[k][0]
    if any(w.lower() in nm.lower() for w in KEY):
        P("   0x%08X  %s" % (k, nm))
OUT.close()
print("ok")
