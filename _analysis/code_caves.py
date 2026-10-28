# -*- coding: utf-8 -*-
"""Find code caves (padding runs) suitable for injected code, and report
overall patching infrastructure facts."""
import io, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

pe = PE()
OUT = r"D:\XiuXian\_analysis\reports\code_caves.txt"
f = io.StringIO()

f.write("### file facts\n")
f.write("  size            : %d bytes (0x%X)\n" % (len(pe.raw), len(pe.raw)))
f.write("  computed end    : 0x%X\n" % max(s["rawptr"] + s["rawsize"] for s in pe.sections))
f.write("  overlay         : %d bytes\n" % (len(pe.raw) - max(s["rawptr"] + s["rawsize"] for s in pe.sections)))
# PE checksum field
ck_off = pe.opt + 64
import struct
f.write("  PE checksum field (file 0x%X) = 0x%X\n" % (ck_off, struct.unpack_from("<I", pe.raw, ck_off)[0]))
f.write("  DllCharacteristics = 0x%X (DYNAMIC_BASE=%s)\n" % (
    struct.unpack_from("<H", pe.raw, pe.opt + 70)[0],
    bool(struct.unpack_from("<H", pe.raw, pe.opt + 70)[0] & 0x40)))
f.write("  Characteristics    = 0x%X\n" % struct.unpack_from("<H", pe.raw, pe.pe_off + 22)[0])

# RELOCATIONS: a code cave in .text that we add code to needs no reloc if we
# only use rel32/absolute-immediate-free instructions. Report reloc count.
f.write("\n### relocation table size (affects adding new code)\n")
rel = [s for s in pe.sections if s["name"] == ".reloc"][0]
f.write("  .reloc rawsize 0x%X\n" % rel["rawsize"])
o = rel["rawptr"]
blocks = 0
tot = 0
while o < rel["rawptr"] + rel["rawsize"] - 8:
    pv, bs = struct.unpack_from("<II", pv_o := pe.raw, o)
    bs = struct.unpack_from("<I", pe.raw, o + 4)[0]
    if bs == 0:
        break
    blocks += 1
    tot += (bs - 8) // 2
    o += bs
f.write("  blocks %d, entries %d\n" % (blocks, tot))

# ---- code caves: runs of 0xCC or 0x00 inside .text ----
trp, tva, trs = pe.text()
text = pe.raw[trp:trp + trs]

def runs(byte, minlen):
    out = []
    i = 0
    while i < len(text):
        if text[i] == byte:
            j = i
            while j < len(text) and text[j] == byte:
                j += 1
            if j - i >= minlen:
                out.append((IMAGE_BASE + tva + i, j - i))
            i = j
        else:
            i += 1
    return out

for byte, name in ((0xCC, "int3 (0xCC)"), (0x00, "zero (0x00)")):
    rr = runs(byte, 32)
    rr.sort(key=lambda x: -x[1])
    f.write("\n### %s runs >= 32 bytes in .text: %d\n" % (name, len(rr)))
    for va, ln in rr[:25]:
        f.write("   VA 0x%08X  len %4d (0x%X)  file 0x%X\n" % (va, ln, ln, pe.va2off(va)))

# Also check .rdata tail and whether last section has slack
f.write("\n### section slack (vsize vs rawsize)\n")
for s in pe.sections:
    f.write("  %-8s vsize 0x%-7X rawsize 0x%-7X slack %d\n"
            % (s["name"], s["vsize"], s["rawsize"], s["rawsize"] - s["vsize"]))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
