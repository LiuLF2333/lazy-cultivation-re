# -*- coding: utf-8 -*-
"""Decode UI labels near ablePt, and find the item->attribute source for type1=132."""
import struct, io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\ablept_label.txt"
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


def va2off(va):
    rva = va - IB
    for nm, sva, vs, rp, rs in secs:
        if sva <= rva < sva + max(vs, rs):
            return rp + (rva - sva)
    return None


def wide_at(va):
    o = va2off(va)
    out = []
    i = o
    while i + 1 < len(raw) and len(out) < 200:
        cp = raw[i] | (raw[i + 1] << 8)
        if cp == 0:
            break
        out.append(cp)
        i += 2
    if len(out) < 2:
        return None
    return bytes(b for cp in out for b in (cp & 0xFF, cp >> 8)).decode("utf-16-le", errors="replace")


f = io.StringIO()
f.write("### strings pushed near the ablePt display sites\n")
for va in [0x68a4f0, 0x68a4f8, 0x68a500, 0x68a508, 0x68a510, 0x68a518, 0x68a520, 0x68a52c, 0x68a9b0, 0x68a9a0, 0x68a9c0]:
    f.write("  0x%X  %r\n" % (va, wide_at(va)))

f.write("\n### the helper 0x426240 (attribute lookup used by type1=132)\n")
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
tn, tva, tvs, trp, trs = [s for s in secs if s[0] == ".text"][0]
md = Cs(CS_ARCH_X86, CS_MODE_32)
off = trp + (0x426240 - IB - tva)
code = raw[off:off + 0x100]
pos = 0
while pos < len(code):
    got = list(md.disasm(code[pos:pos + 15], 0x426240 + pos, count=1))
    if not got:
        f.write("0x%08X  db 0x%02X\n" % (0x426240 + pos, code[pos]))
        pos += 1
        continue
    i = got[0]
    f.write("0x%08X  %-22s %s %s\n" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
    pos += i.size

# Where does the item runtime +0x278 / +0x294 come from?
f.write("\n### dword 0x294 and 0x278 constant refs (struct offsets)\n")
text = raw[trp:trp + trs]
for pat in [b"\x94\x02\x00\x00", b"\x78\x02\x00\x00"]:
    cnt = 0
    pos = 0
    while cnt < 12:
        i = text.find(pat, pos)
        if i < 0:
            break
        if i >= 1:
            f.write("  %s at VA 0x%X (pre=%02X)\n" % (pat.hex(), IB + tva + i, text[i - 1]))
            cnt += 1
        pos = i + 1

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
