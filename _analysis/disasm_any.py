import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
pe = PE(sys.argv[1])
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
va = int(sys.argv[2], 16)
size = int(sys.argv[3], 16)
for i in md.disasm(pe.bytes_at(va, size), va):
    print("%08X  %-24s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
