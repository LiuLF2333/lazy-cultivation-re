# -*- coding: utf-8 -*-
"""Disassemble the 5 known chooser call-site regions and dump the title strings."""
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_03_sites.txt", "w", encoding="utf-8")
def P(*a):
    OUT.write(" ".join(str(x) for x in a) + "\n")

pe = PE()

# (start_va_to_dump, nbytes, label)
REGIONS = [
    (0x4A0040, 0x180, "site: 选择携带的物品 (push@0x4A00D4, show@0x4A0110)"),
    (0x49FDE0, 0x180, "site: 选择派遣的宠物 (push@0x49FE76, show@0x49FEB2)"),
    (0x408190, 0x140, "site: 选择让[%s]遗忘... (push@0x408225)"),
]
for va, n, label in REGIONS:
    P("=" * 100)
    P("%s   from 0x%08X for 0x%X bytes  off=0x%X" % (label, va, n, pe.va2off(va)))
    P("=" * 100)
    for ins in disasm(pe, va, n):
        P("   " + fmt(ins))
    P("")

P("#" * 100)
P("TITLE STRINGS")
P("#" * 100)
for va in (0x68E9CC, 0x68E960, 0x68FFE4, 0x68F394, 0x69145C, 0x67F734, 0x68EDEC):
    P("0x%08X : %r" % (va, pe.wide(va)))
    P("      raw: %s" % pe.bytes_at(va, 64).hex())

P("")
P("#" * 100)
P("file offset 0xAD8CA / 0xB3E18 / 0xBBAE7 -> VA")
P("#" * 100)
for off in (0xAD8CA, 0xB3E18, 0xBBAE7):
    P("off 0x%X -> VA 0x%X" % (off, pe.off2va(off)))
OUT.close()
print("ok")
