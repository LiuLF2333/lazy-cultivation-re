# -*- coding: utf-8 -*-
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

def dump(a, n, tag=""):
    W("--- %s 0x%08X .. 0x%08X ---" % (tag, a, a+n))
    for ins in disasm(pe, a, n):
        W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
    W("")

dump(0x43a290, 0x80, "43a290")
dump(0x432180, 0x80, "432180")
dump(0x439680, 0xC0, "439680")
dump(0x4396f0, 0x80, "4396f0")
dump(0x48e800, 0x60, "48e800")
dump(0x4261d0, 0x70, "4261d0")

W("=== refs to ItemTable.gjd wide 0x683386 / 0x683360 ===")
for v in (0x683360, 0x683386, 0x683624, 0x683662, 0x68EDEC):
    W("  dword ptr refs to 0x%08X: %s" % (v, [hex(x) for x in pe.find_dword_va(v)]))
    W("  push imm refs: %s" % [hex(x) for x in pe.find_push_imm(v)])

# also look at 0x683300..0x683400 wide strings
W("")
W("=== wide strings near 0x683300..0x6833A0 ===")
for va in range(0x683300, 0x6833A0, 4):
    w = pe.wide(va)
    if w and len(w) > 1:
        W("  0x%08X %r" % (va, w))

open(r"D:\XiuXian\_analysis\re\s3_helpers.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
