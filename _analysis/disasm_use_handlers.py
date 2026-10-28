# -*- coding: utf-8 -*-
"""Disassemble the item-use handlers called from the use-dispatcher @0x20B000."""
import struct, io
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\disasm_use_handlers.txt"
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


def disasm(start_va, nbytes, label, f):
    f.write("\n" + "=" * 78 + "\n")
    f.write("%s   VA 0x%X\n" % (label, start_va))
    f.write("=" * 78 + "\n")
    off = trp + (start_va - IB - tva)
    code = raw[off:off + nbytes]
    pos = 0
    while pos < len(code):
        got = list(md.disasm(code[pos:pos + 15], start_va + pos, count=1))
        if not got:
            f.write("0x%08X  db 0x%02X\n" % (start_va + pos, code[pos]))
            pos += 1
            continue
        ins = got[0]
        f.write("0x%08X  %-24s %s %s\n" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        pos += ins.size


f = io.StringIO()
f.write("Item-use dispatcher @0x20B000 -> handler calls\n")
f.write("  type1=105 (0x69) -> 0x20BF89\n")
f.write("  type1=110 (0x6E) -> 0x20C0D3   <== RANDOM BASE ATTRIBUTE pill\n")
f.write("  type1=111 (0x6F) -> 0x20C147\n")
f.write("  type1=112 (0x70) -> 0x20C166\n")
f.write("  type1=128 (0x80) -> 0x20BACF\n")

# type1=110 handler: the random-attribute pill
disasm(0x20C0D3, 0x180, "type1=110 handler (random base attribute)", f)
# type1=111 close relative
disasm(0x20C147, 0x120, "type1=111 handler", f)
# type1=105 for comparison (also grants attribute points)
disasm(0x20BF89, 0x180, "type1=105 handler (grants 境界点/attribute points)", f)

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
