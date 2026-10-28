# -*- coding: utf-8 -*-
"""List accesses to battle-object fields (instruction-accurate)."""
import sys, struct, bisect
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p = PE(r"D:\XiuXian\懒人修仙传.exe")
d = p.raw
TEXT = next(s for s in p.sections if s["name"] == ".text")
TS, TE = TEXT["rawptr"], TEXT["rawptr"] + TEXT["rawsize"]
md = Cs(CS_ARCH_X86, CS_MODE_32)

insns = list(md.disasm(d[TS:TS + TEXT["rawsize"]], 0x401000))
starts = [x.address for x in insns]
print("decoded", len(insns), "instructions")

def containing(va):
    k = bisect.bisect_right(starts, va) - 1
    if k < 0:
        return None
    ins = insns[k]
    if ins.address <= va < ins.address + ins.size:
        return ins
    return None

FIELDS = [0x3C, 0x40, 0x44, 0x48, 0x4C, 0x5A0, 0x5A4, 0x5A8, 0x5B4, 0x5B8, 0x5BC, 0x5FC, 0x600]
for f in FIELDS:
    print("==== +0x%X ====" % f)
    needle = struct.pack("<I", f)
    i = TS
    seen = set()
    while True:
        i = d.find(needle, i, TE)
        if i < 0:
            break
        va = p.off2va(i)
        ins = containing(va)
        if ins and ("0x%x" % f) in ins.op_str and ins.address not in seen:
            seen.add(ins.address)
            print("  %08X  %-20s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        i += 1
    print()
