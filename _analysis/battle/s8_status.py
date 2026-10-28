# -*- coding: utf-8 -*-
"""Find all writes/reads of the battle status field [obj+0x4C]."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p = PE(r"D:\XiuXian\懒人修仙传.exe")
d = p.raw
TEXT = next(s for s in p.sections if s["name"] == ".text")
md = Cs(CS_ARCH_X86, CS_MODE_32)
for ins in md.disasm(d[TEXT["rawptr"]:TEXT["rawptr"] + TEXT["rawsize"]], 0x401000):
    if ", 0x4c]" in ins.op_str or "[eax + 0x4c]" in ins.op_str or "[ecx + 0x4c]" in ins.op_str \
       or "[edx + 0x4c]" in ins.op_str or "[esi + 0x4c]" in ins.op_str or "[edi + 0x4c]" in ins.op_str \
       or "[ebx + 0x4c]" in ins.op_str:
        if ins.address < 0x491000:
            print("%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
