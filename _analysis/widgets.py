# -*- coding: utf-8 -*-
import struct, sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
raw = pe.raw
out = io.StringIO()
def p(*a): print(*a, file=out)

# find immediate pushes of 0x6bc980
pat = struct.pack("<I", 0x6bc980)
i = 0
hits = []
while True:
    i = raw.find(pat, i)
    if i == -1:
        break
    # check preceding byte is 0x68 (push imm32)
    if i >= 1 and raw[i-1] == 0x68:
        # file offset -> VA: use PE section mapping via va2off reverse
        hits.append(i)
    i += 1
p("push 0x6bc980 sites (file offsets):", ["0x%X" % h for h in hits])

# try to map to VA by brute force section table
def off2va(off):
    # parse sections
    import struct as st
    nsec = st.unpack_from("<H", raw, 0x06)[0]
    opt = 0x18
    secoff = opt + st.unpack_from("<H", raw, 0x14)[0]
    for k in range(nsec):
        o = secoff + k*40
        name = raw[o:o+8].rstrip(b"\x00")
        vsize, vaddr, rsize, rptr = st.unpack_from("<IIII", raw, o+8)
        if rptr <= off < rptr + max(rsize, vsize):
            return IMAGE_BASE + vaddr + (off - rptr)
    return None

for h in hits:
    p("   0x%X -> VA 0x%X" % (h, off2va(h) or 0))

# dump the widget helper family 0x40a000-0x40a500 as mnemonic summary
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md = Cs(CS_ARCH_X86, CS_MODE_32)
p("")
p("==== widget helpers 0x40A0C0..0x40A4C0 (first insn of each func) ====")
start = 0x40A0C0
off = pe.va2off(start)
end = pe.va2off(0x40A4C0)
o = off
while o < end:
    if raw[o] == 0x55 and raw[o+1] == 0x8b and raw[o+2] == 0xec:
        va = off2va(o)
        if va is None:
            o += 1
            continue
        ins = list(md.disasm(raw[o:o+16], va))
        p("  0x%08X  %s" % (va, " ; ".join("%s %s" % (x.mnemonic, x.op_str) for x in ins[:3])))
    o += 1
open(r"D:\XiuXian\_analysis\reports\widgets.txt", "w", encoding="utf-8").write(out.getvalue())
print("ok")
