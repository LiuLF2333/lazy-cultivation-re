# -*- coding: utf-8 -*-
"""Locate the function containing the xref 0x41604B (attribute-gain message)
by scanning backwards for a prologue, then disassemble it fully."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\attr_func.txt"
f = io.StringIO()

# find function start: scan back for 55 8B EC (push ebp / mov ebp,esp)
def find_start(va, back=0x400):
    o = pe.va2off(va)
    for k in range(1, back):
        p = o - k
        if pe.raw[p] == 0x55 and pe.raw[p + 1] == 0x8B and pe.raw[p + 2] == 0xEC:
            # check previous byte is int3/ret/padding (likely boundary)
            prev = pe.raw[p - 1]
            if prev in (0xCC, 0xC3, 0x00, 0x90):
                return pe.off2va(p)
    return None

for target in (0x41604B, 0x416041):
    s = find_start(target)
    f.write("### xref 0x%X -> function start 0x%X\n" % (target, s if s else -1))

s = find_start(0x41604B)
if s:
    f.write("\n### full disassembly from 0x%X\n" % s)
    insns = list(disasm(pe, s, 0x300))
    for ins in insns:
        f.write(fmt(ins) + "\n")
    f.write("\n### string pushes\n")
    for va, b, m, o in insns:
        if m == "push" and o.startswith("0x"):
            v = int(o, 16)
            if 0x600000 < v < 0x6D0000:
                f.write("  0x%08X push %s -> %r\n" % (va, o, pe.wide(v, 90)))
    f.write("\n### calls\n")
    for va, b, m, o in insns:
        if m == "call" and o.startswith("0x"):
            f.write("  0x%08X call %s\n" % (va, o))

# Also: the other attribute-apply path - find code that writes the six base attrs
f.write("\n\n### searching for 6 consecutive attribute adds (stride pattern)\n")
# look for imul reg, reg, imm or repeated add [reg+disp]
open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok start=%s" % (hex(s) if s else None))
