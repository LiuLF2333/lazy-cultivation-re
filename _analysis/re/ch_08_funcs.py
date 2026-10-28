# -*- coding: utf-8 -*-
"""Function-start finder, enclosing-function dumps, helper bodies, vtable resolution."""
import sys, struct, re
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_08_funcs.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE(); raw = pe.raw
TRP, TVA, TRS = pe.text()
TEXT_END = IMAGE_BASE + TVA + TRS

PAD = {0xCC, 0x90}

def is_pad_byte(v):
    return v in (0xCC, 0x90)

def func_start(va):
    """Scan backwards for a plausible function start: a `push ebp; mov ebp,esp`
       (55 8B EC) preceded by >=2 padding bytes, or the previous `ret` + padding."""
    off = pe.va2off(va)
    for back in range(2, 0x4000):
        o = off - back
        if o < TRP:
            break
        if raw[o:o+3] == b"\x55\x8b\xec":
            # require padding right before
            if o - 2 >= TRP and is_pad_byte(raw[o-2]) and is_pad_byte(raw[o-1]):
                return pe.off2va(o)
        # also accept start-of-text
    return None

def dump_fn(va, label, maxb=0x1400):
    st = func_start(va) or va
    P("=" * 100)
    P("%s : enclosing function 0x%08X (site 0x%08X, off 0x%X)" % (label, st, va, pe.va2off(st)))
    P("=" * 100)
    n = 0
    for ins in disasm(pe, st, maxb):
        P("   " + fmt(ins))
        n += 1
        if n > 700:
            P("   ... (truncated)")
            break
    P("")

for va, lb in [(0x4A00D4, "选择携带的物品"), (0x49FE76, "选择派遣的宠物"), (0x408225, "选择让[..]遗忘")]:
    dump_fn(va, lb)

P("#" * 100)
P("HELPER BODIES")
P("#" * 100)
def dump(va, n, label=""):
    P("=" * 96)
    P("0x%08X  (%s)  off=0x%X" % (va, label, pe.va2off(va)))
    P("=" * 96)
    for ins in disasm(pe, va, n):
        P("   " + fmt(ins))
    P("")

for va, n, lb in [
    (0x435EB0, 0x120, "5-arg helper, dest=[ebp+8]"),
    (0x4A17C0, 0x80, "returns al, called right after 0x40A620"),
    (0x421640, 0x40, "real title setter"),
    (0x420FF0, 0x40, ""),
    (0x421290, 0x80, ""),
    (0x4A00E0 if False else 0x40A230, 0x10, "skip"),
]:
    dump(va, n, lb)

P("#" * 100)
P("VTL / RTTI resolution for 0x648258 and 0x693014")
P("#" * 100)
# TypeDescriptor names
names = {}
for s in pe.sections:
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    i = a
    while i < b - 8:
        if raw[i:i+4] in (b".?AV", b".?AU"):
            j = i; ch = []
            while j < b and 0x20 <= raw[j] < 0x7f:
                ch.append(chr(raw[j])); j += 1
            if raw[j] == 0 and len(ch) > 5:
                names[pe.off2va(i)] = "".join(ch); i = j + 1; continue
        i += 1
td2name = {nva - 8: nm for nva, nm in names.items()}
P("TD VAs: %d" % len(td2name))

# loose COL scan: A[0]=sig in (0,1), A[4]=0, A[12]=TD VA, A[16] plausible ptr, and *(A-4)==A
cols = {}
for s in pe.sections:
    if s["name"] not in (".rdata", ".data"):
        continue
    a, b = s["rawptr"], s["rawptr"] + s["rawsize"]
    for i in range(a + 4, b - 0x14, 4):
        A = pe.off2va(i)
        sig, off_, cd, ptd, pcd = struct.unpack_from("<IIIII", raw, i)
        if off_ != 0:
            continue
        if ptd not in td2name:
            continue
        if not (0x645000 <= pcd < 0x6D3000):
            continue
        if pe.u32(A - 4) != A:
            continue
        cols[A] = (td2name[ptd], sig, cd, pcd)
P("COLs found (loose): %d" % len(cols))

def resolve(vt):
    c = pe.u32(vt - 4)
    return cols.get(c)

for vt in (0x648258, 0x693014, 0x6930A0):
    P("vtable 0x%08X : col=0x%X -> %s" % (vt, pe.u32(vt-4) or 0, resolve(vt)))

P("")
P("All COLs:")
for k in sorted(cols):
    P("   0x%08X sig=%d %s" % (k, cols[k][1], cols[k][0]))

P("")
P("Vtable dumps (first 24 entries, resolved to function names where possible):")
for vt in (0x648258, 0x693014, 0x6930A0):
    P("---- vtable 0x%08X  (%s)" % (vt, resolve(vt)))
    for i in range(24):
        f = pe.u32(vt + i*4)
        if f is None: break
        P("      [+0x%02X] 0x%08X" % (i*4, f))
    P("")
OUT.close()
print("ok")
