# -*- coding: utf-8 -*-
"""Find the item-use switch jump table and map type1 -> handler VA."""
import struct, io

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\switch_table.txt"

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


def off2rva(off):
    for nm, va, vs, rp, rs in secs:
        if rp <= off < rp + rs:
            return va + (off - rp)
    return None


# scan for: FF 24 85 <imm32>  = jmp dword ptr [eax*4 + imm32]
lines = []
found = []
st = 0
while True:
    i = text.find(b"\xff\x24\x85", st)
    if i < 0:
        break
    st = i + 1
    imm = struct.unpack_from("<I", text, i + 3)[0]
    # imm is an absolute VA (image base 0x400000)
    target_rva = imm - 0x400000
    off = rva2off(target_rva)
    if off is None:
        continue
    # read up to 64 entries; entries must be valid VAs in .text
    entries = []
    for k in range(64):
        v = struct.unpack_from("<I", raw, off + k * 4)[0]
        r = v - 0x400000
        o2 = rva2off(r)
        if o2 is None or not (tva <= r < tva + tvs):
            break
        entries.append(v)
    if len(entries) >= 8:
        found.append((i, imm, target_rva, len(entries), entries))

found.sort(key=lambda x: -x[3])
lines.append("Candidate switch tables (jmp [eax*4+imm]), sorted by entry count:\n")
for off, imm, trva, n, entries in found[:12]:
    lines.append("  jmp at VA 0x%X -> table VA 0x%X (RVA 0x%X) entries=%d"
                 % (tva + off, imm, trva, n))
    lines.append("      handler VAs: %s" % [hex(e) for e in entries[:40]])
    lines.append("")

if found:
    off, imm, trva, n, entries = found[0]
    lines.append("=" * 70)
    lines.append("BEST TABLE: VA 0x%X, %d entries" % (imm, n))
    lines.append("Documented ItemTable type1 values: 100,105,106,107,108,110,112,113,114,115,")
    lines.append("116,117,118,119,120,121,122,123,124,126,127,128,129,130,131,132,200,201,")
    lines.append("202,203,204,300,302,303")
    lines.append("")
    lines.append("Hypothesis check: if the switch base corresponds to type1=100, then")
    lines.append("entry[0] is type1=100. Index arithmetic below shows both alignments:")
    for shift in (100, 0):
        lines.append("  -- assuming entry[0] == type1 %d" % shift)
        for k, e in enumerate(entries):
            lines.append("     type1=%-5d -> handler VA 0x%X" % (k + shift, e))
        lines.append("")

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("\n".join(lines[:40]))
