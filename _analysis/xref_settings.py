import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = PE(r"D:\XiuXian\懒人修仙传.exe.bak.20261019-193436-571623")
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
trp, tva, trs = pe.text()
code = pe.raw[trp:trp + trs]
base = 0x400000 + tva

# Linear disassembly, collect immediates of interest.
targets = {137, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073,
           1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083,
           1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093,
           1094, 1095, 1096, 1097, 1098, 1099}
hits = []
pos = 0
while pos < len(code):
    got = list(md.disasm(code[pos:pos + 15], base + pos, count=1))
    if not got:
        pos += 1
        continue
    ins = got[0]
    try:
        ops = ins.operands
        if len(ops) >= 2 and ops[1].type == 2:
            imm = ops[1].imm & 0xFFFFFFFF
            if imm in targets:
                hits.append((ins.address, ins.mnemonic, ins.op_str, imm))
    except Exception:
        pass
    pos += ins.size

for va, mn, ops, imm in hits:
    print("0x%08X  %-8s %-30s imm=%d" % (va, mn, ops, imm))
print("hits", len(hits))
