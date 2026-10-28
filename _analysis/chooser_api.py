# -*- coding: utf-8 -*-
import struct, sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
md = Cs(CS_ARCH_X86, CS_MODE_32)

out = io.StringIO()
def dump(start, n, title):
    print("", file=out)
    print("==== %s VA 0x%08X ====" % (title, start), file=out)
    off = pe.va2off(start)
    if off is None:
        print("   <unmapped>", file=out); return
    for ins in md.disasm(pe.raw[off:off+n], start):
        print("  0x%08X  %-18s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str), file=out)

dump(0x4216B0, 0x90, "A chooser-init 0x4216B0")
dump(0x4219B0, 0x70, "B 0x4219B0")
dump(0x4041A0, 0x30, "C 0x4041A0")
dump(0x421730, 0x40, "D chooser-add 0x421730")
dump(0x40A5D0, 0x30, "E 0x40A5D0")
dump(0x40A560, 0x40, "F 0x40A560")
dump(0x40A600, 0x30, "G 0x40A600")
dump(0x40A620, 0x30, "H chooser-fin 0x40A620")
dump(0x40AA40, 0x20, "I 0x40AA40")
dump(0x40A6F0, 0x70, "J 0x40A6F0")
dump(0x40A480, 0x40, "K 0x40A480")
dump(0x4065E0, 0x20, "L 0x4065E0")
dump(0x421360, 0x50, "M 0x421360")

open(r"D:\XiuXian\_analysis\reports\chooser_api.txt", "w", encoding="utf-8").write(out.getvalue())
print("ok")
