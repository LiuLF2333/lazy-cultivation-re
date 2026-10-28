# -*- coding: utf-8 -*-
"""Find code that reads or writes the wild-pet repeat-dispatch fields."""
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_MEM

pe = PE(sys.argv[1])
text = next(s for s in pe.sections if s["name"] == ".text")
base = 0x400000 + text["va"]
data = pe.raw[text["rawptr"]:text["rawptr"] + text["rawsize"]]
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True

for ins in md.disasm(data, base):
    if ins.id == 0:
        continue
    if not (0x49F000 <= ins.address < 0x4A2000):
        continue
    for op in ins.operands:
        if op.type == CS_OP_MEM and op.mem.disp in (0x54, 0x58, 0x5C):
            print("%08X  %-24s %s %s" % (
                ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
            break
