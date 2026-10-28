# -*- coding: utf-8 -*-
"""Disassemble the item-use dispatch cluster with capstone."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\disasm_itemuse.txt"

raw = open(EXE, "rb").read()
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
text = raw[trp:trp + trs]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

lines = []
# The dispatch cluster: disassemble a generous window around VA 0x20B000
START_VA = 0x20A900
END_VA = 0x20BC00
start_off = START_VA - tva
end_off = END_VA - tva
code = text[start_off:end_off]

lines.append("Disassembly of item-use dispatch cluster  VA 0x%X - 0x%X" % (START_VA, END_VA))
lines.append("=" * 78)

# Resync-capable linear sweep: if a byte doesn't decode, emit db and advance.
pos = 0
while pos < len(code):
    ins_list = list(md.disasm(code[pos:pos + 16], START_VA + pos, count=1))
    if not ins_list:
        lines.append("0x%08X  %-24s db 0x%02X" % (START_VA + pos, "%02x" % code[pos], code[pos]))
        pos += 1
        continue
    ins = ins_list[0]
    lines.append("0x%08X  %-24s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    pos += ins.size

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("wrote %d instructions" % len(lines))
