# -*- coding: utf-8 -*-
"""Disassemble the located item-use dispatch handlers (type1 100..132)."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\disasm_itemuse_handlers.txt"

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


def rva2off(rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None


md = Cs(CS_ARCH_X86, CS_MODE_32)

lines = []
lines.append("Item-use dispatch table @ VA 0x418CA8  (base type1=100, 33 entries)")
lines.append("jmp [eax*4+0x418CA8] at VA 0x1840C")
lines.append("=" * 78)

TABLE = 0x418CA8
entries = []
for k in range(33):
    v = struct.unpack_from("<I", raw, rva2off(TABLE - 0x400000) + k * 4)[0]
    entries.append(v)
    lines.append("  type1=%-4d -> 0x%X" % (100 + k, v))

lines.append("")
lines.append("=" * 78)
lines.append("Disassembly of the whole handler block 0x418400 - 0x418D00")
lines.append("=" * 78)

# Real VAs are ImageBase(0x400000)+RVA; .text VA range is 0x401000..0x64462A.
IMAGE_BASE = 0x400000
START, END = 0x418400, 0x418D00
start_off = trp + (START - IMAGE_BASE - tva)
end_off = trp + (END - IMAGE_BASE - tva)
code = raw[start_off:end_off]
pos = 0
while pos < len(code):
    got = list(md.disasm(code[pos:pos + 15], START + pos, count=1))
    if not got:
        lines.append("0x%08X  db 0x%02X" % (START + pos, code[pos]))
        pos += 1
        continue
    ins = got[0]
    mark = ""
    if ins.address in entries:
        mark = "   <== HANDLER type1=%s" % [100 + i for i, e in enumerate(entries) if e == ins.address]
    lines.append("0x%08X  %-22s %s %s%s"
                 % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
    pos += ins.size

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("instructions:", len(lines))
