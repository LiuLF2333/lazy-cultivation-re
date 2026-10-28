# -*- coding: utf-8 -*-
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, x86_const
pe = PE(sys.argv[1])
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
trp, tva, trs = pe.text()
code = pe.raw[trp:trp+trs]
off = 0
while off < len(code):
    ins = list(md.disasm(code[off:off+15], 0x400000+tva+off, count=1))
    if not ins:
        off += 1; continue
    i = ins[0]
    mem = [o for o in i.operands if o.type == x86_const.X86_OP_MEM]
    hit = None
    for o in mem:
        if o.mem.disp in (0x1894,0x1898,0x2428,0x9cc,0x9d8,0x9c0):
            hit = o.mem.disp
    if hit is not None:
        print("%08X %-24s %-8s %s   [disp=%X]" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str, hit))
    off += i.size
