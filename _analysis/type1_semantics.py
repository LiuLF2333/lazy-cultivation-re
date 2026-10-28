# -*- coding: utf-8 -*-
"""Extract the full type1 -> tooltip-format-string map from the desc builder."""
import struct, io, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\type1_semantics.txt"
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


def wide_at(va, maxlen=500):
    o = va2off(va)
    if o is None:
        return None
    out = []
    i = o
    while i + 1 < len(raw) and len(out) < maxlen:
        cp = raw[i] | (raw[i + 1] << 8)
        if cp == 0:
            break
        out.append(cp)
        i += 2
    if len(out) < 2:
        return None
    return bytes(b for cp in out for b in (cp & 0xFF, cp >> 8)).decode("utf-16-le", errors="replace")


# Disassemble the desc-builder block and collect push imm32 into .rdata
tn, tva, tvs, trp, trs = [s for s in secs if s[0] == ".text"][0]
md = Cs(CS_ARCH_X86, CS_MODE_32)

TABLE = 0x418CA8
entries = []
for k in range(33):
    entries.append(struct.unpack_from("<I", raw, va2off(TABLE) + k * 4)[0])

START, END = 0x418400, 0x418D00
off = trp + (START - IB - tva)
code = raw[off:off + (END - START)]

# map instruction address -> pushed strings
insns = []
pos = 0
while pos < len(code):
    got = list(md.disasm(code[pos:pos + 15], START + pos, count=1))
    if not got:
        pos += 1
        continue
    insns.append(got[0])
    pos += got[0].size

lines = []
lines.append("Complete type1 -> behaviour map (from tooltip builder @0x418400)")
lines.append("Jump table VA 0x418CA8, base type1 = 100, 33 entries")
lines.append("=" * 78)

for k, hva in enumerate(entries):
    t1 = 100 + k
    # find the handler instructions from hva up to the next jmp 0x418c80
    hs = [i for i, ins in enumerate(insns) if ins.address == hva]
    strs = []
    if hs:
        for ins in insns[hs[0]:hs[0] + 60]:
            if ins.mnemonic == "push" and ins.op_str.startswith("0x"):
                try:
                    v = int(ins.op_str, 16)
                except ValueError:
                    continue
                s = wide_at(v)
                if s and len(s.strip()) > 1:
                    strs.append(s)
            if ins.mnemonic == "jmp" and "0x418c80" in ins.op_str:
                break
    lines.append("type1=%-4d handler=0x%X" % (t1, hva))
    if strs:
        for s in strs:
            lines.append("        %r" % s)
    else:
        lines.append("        (no format string pushed)")

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("ok")
