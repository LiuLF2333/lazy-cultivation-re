# -*- coding: utf-8 -*-
"""Dump disassembly for a VA range."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p = PE(r"D:\XiuXian\懒人修仙传.exe")
md = Cs(CS_ARCH_X86, CS_MODE_32)

start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
o = p.va2off(start)
code = p.raw[o:o + (end - start)]
for ins in md.disasm(code, start):
    print("%08X  %-24s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
