# -*- coding: utf-8 -*-
"""Examine the two ablePt (可分配属性点数) reference sites to see read vs write."""
import struct, io
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\ablept_sites.txt"
raw = open(EXE, "rb").read()
IB = 0x400000

pe = struct.unpack_from("<I", raw, 0x3c)[0]
nsec = struct.unpack_from("<H", raw, pe + 6)[0]
opt = pe + 24
sec = opt + struct.unpack_from("<H", raw, pe + 20)[0]
secs = []
for i in range(nsec):
    o = sec + i * 40
    nm = raw[o:o + 8].rstrip(b"\x00").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", raw, o + 8)
    secs.append((nm, va, vs, rp, rs))
tn, tva, tvs, trp, trs = [s for s in secs if s[0] == ".text"][0]
md = Cs(CS_ARCH_X86, CS_MODE_32)


def dis(start, n, f, label):
    f.write("\n" + "=" * 76 + "\n%s  VA 0x%X\n" % (label, start) + "=" * 76 + "\n")
    off = trp + (start - IB - tva)
    code = raw[off:off + n]
    pos = 0
    while pos < len(code):
        got = list(md.disasm(code[pos:pos + 15], start + pos, count=1))
        if not got:
            f.write("0x%08X  db 0x%02X\n" % (start + pos, code[pos]))
            pos += 1
            continue
        i = got[0]
        f.write("0x%08X  %-22s %s %s\n" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
        pos += i.size


f = io.StringIO()
dis(0x481900, 0x100, f, "ablePt ref #1 (call site 0x481961)")
dis(0x4847A0, 0x100, f, "ablePt ref #2 (call site 0x4847fe)")

# Find functions referencing the attribute-index field +0x294 seen in type1=132
f.write("\n\n### code referencing [reg+0x294]\n")
text = raw[trp:trp + trs]
pat = b"\x94\x02\x00\x00"
cnt = 0
pos = 0
while cnt < 25:
    i = text.find(pat, pos)
    if i < 0:
        break
    # check preceding byte is a modrm with disp32 for mov (8B xx 94 02 00 00)
    if i >= 2 and text[i - 2] == 0x8B:
        f.write("  0x%08X  %s\n" % (IB + tva + i - 2, text[i - 2:i + 4].hex()))
        cnt += 1
    pos = i + 1

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
