# -*- coding: utf-8 -*-
"""Scan .text for accesses to the battle runtime object's fields."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p = PE(r"D:\XiuXian\懒人修仙传.exe")
d = p.raw
TEXT = next(s for s in p.sections if s["name"] == ".text")
TS, TE = TEXT["rawptr"], TEXT["rawptr"] + TEXT["rawsize"]
md = Cs(CS_ARCH_X86, CS_MODE_32)

FIELDS = [0x24F4, 0x570, 0x574, 0x578, 0x57C, 0x5B0, 0x5B4]

def dec_at(va, n=40, back=10):
    o = p.va2off(va)
    start = max(TS, o - back)
    return list(md.disasm(d[start:o + n], p.off2va(start)))

for f in FIELDS:
    print("==== disp 0x%X ====" % f)
    needle = struct.pack("<I", f)
    i = TS
    count = 0
    while True:
        i = d.find(needle, i, TE)
        if i < 0:
            break
        insns = [x for x in dec_at(p.off2va(i), 12, 12)
                 if x.address <= p.off2va(i) < x.address + x.size]
        if insns:
            ins = insns[0]
            if f"0x{f:x}" in ins.op_str:
                # find enclosing function start (nearest 0xCC padding then push ebp)
                sig = "%08X %-20s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str)
                print("  " + sig)
                count += 1
        i += 1
    print("  (%d)" % count)
    print()
