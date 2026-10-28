# -*- coding: utf-8 -*-
"""Disassemble the MOD Data/Res override logic."""
import struct, io
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\disasm_mod_override.txt"
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
dis(0x4CA100, 0x1C0, f, "MOD path build / override (Mods\\, \\Res\\, \\Data\\)")
dis(0x4C7980, 0x140, f, "MOD scan (Mods\\ @0x4c79e2)")
open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
