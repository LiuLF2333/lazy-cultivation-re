# -*- coding: utf-8 -*-
"""Find all references to the game timer IDs (0x3E9..0x3F1) in .text."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p = PE(r"D:\XiuXian\懒人修仙传.exe")
d = p.raw
TEXT = next(s for s in p.sections if s["name"] == ".text")
TS, TE = TEXT["rawptr"], TEXT["rawptr"] + TEXT["rawsize"]
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dec_at(va, n=20):
    o = p.va2off(va)
    return list(md.disasm(d[o:o + n], va))

for tid in range(0x3E9, 0x3F2):
    print("==== timer id 0x%X (%d) ====" % (tid, tid))
    needle = struct.pack("<I", tid)
    i = TS
    seen = []
    while True:
        i = d.find(needle, i, TE)
        if i < 0:
            break
        # decode at i-6 .. i+6
        start = max(TS, i - 8)
        insns = list(md.disasm(d[start:i + 8], p.off2va(start)))
        # find the instruction that contains offset i
        iva = p.off2va(i)
        ctx = []
        for ins in insns:
            if ins.address - 6 <= iva <= ins.address + ins.size + 6:
                ctx.append("%s %s" % (ins.mnemonic, ins.op_str))
        print("  off 0x%06X va 0x%08X : %s" % (i, iva, " | ".join(ctx)))
        seen.append(i)
        i += 1
    print()
