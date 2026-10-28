# -*- coding: utf-8 -*-
import struct, sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
raw = pe.raw
out = io.StringIO()

def p(*a):
    print(*a, file=out)

def va2off(va):
    return pe.va2off(va)

def off2va(off):
    if hasattr(pe, "off2va"):
        return pe.off2va(off)
    return off + 0x400000

# locate .text
text_va = 0x401000
text_off = va2off(text_va)
text_size = 0x240000  # enough

def call_sites(target):
    res = []
    pat = b"\xe8"
    i = text_off
    end = text_off + text_size
    while True:
        j = raw.find(pat, i, end)
        if j == -1:
            break
        rel = struct.unpack_from("<i", raw, j + 1)[0]
        site_va = off2va(j)
        if site_va + 5 + rel == target:
            res.append(site_va)
        i = j + 1
    return res

def func_start(va, limit=0x3000):
    off = va2off(va)
    o = off
    while o > off - limit:
        if o - 1 >= 0 and raw[o-1] in (0xC3, 0xCC) and raw[o] == 0x55:
            return off2va(o)
        o -= 1
    return None

for target, name in [(0x4216B0, "chooser-init 0x4216B0"),
                     (0x421730, "chooser-add  0x421730"),
                     (0x40A620, "chooser-fin  0x40A620")]:
    sites = call_sites(target)
    p("==== %s : %d call sites ====" % (name, len(sites)))
    fs = {}
    for s in sites:
        f = func_start(s)
        fs.setdefault(f, []).append(s)
    for f in sorted(fs, key=lambda x: (x is None, x or 0)):
        fname = "0x%08X" % f if f is not None else "?"
        p("   func %s  sites: %s" % (fname, ", ".join("0x%X" % x for x in fs[f][:6])))
    p("")

open(r"D:\XiuXian\_analysis\reports\chooser_callsites.txt", "w", encoding="utf-8").write(out.getvalue())
print("ok")
