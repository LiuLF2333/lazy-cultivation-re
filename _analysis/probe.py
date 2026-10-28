# -*- coding: utf-8 -*-
import struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
md = Cs(CS_ARCH_X86, CS_MODE_32)

def wstr(va):
    off = pe.va2off(va)
    if off is None:
        return "<no>"
    end = off
    while pe.raw[end:end+2] not in (b"\x00\x00", b""):
        end += 2
    return pe.raw[off:end].decode("utf-16-le", "replace")

def astr(va):
    off = pe.va2off(va)
    if off is None:
        return "<no>"
    return pe.raw[off:].split(b"\x00")[0].decode("latin1", "replace")

for va in (0x6bc980, 0x68e9cc, 0x68e98c, 0x68ffe4, 0x67f734, 0x631008):
    print("0x%08X w: %r   a: %r" % (va, wstr(va), astr(va)))

print()
print("refs to 0x6bc980:")
data = pe.raw
pat = struct.pack("<I", 0x6bc980)
i = data.find(pat)
cnt = 0
while i != -1 and cnt < 20:
    va = None
    for s in pe.sections if hasattr(pe, "sections") else []:
        pass
    # map file offset to VA using pe helper if available
    try:
        va = pe.off2va(i)
    except Exception:
        va = i + 0x400000
    print("  file 0x%X va 0x%X" % (i, va))
    cnt += 1
    i = data.find(pat, i + 1)
print("  total shown", cnt)

print()
print("sections:")
for s in getattr(pe, "sections", []):
    print("  ", s)
