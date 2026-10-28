# -*- coding: utf-8 -*-
"""Check: (a) can an item grant ablePt (allocation points)? (b) how does
type1=132 resolve its attribute name?  (c) does MOds override work?"""
import struct, io
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\ablept_132.txt"
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
text = raw[trp:trp + trs]
md = Cs(CS_ARCH_X86, CS_MODE_32)

f = io.StringIO()

# ---- (a) find narrow "ablePt" occurrences ----
f.write("### (a) 'ablePt' occurrences (narrow)\n")
st = 0
offs = []
while True:
    i = raw.find(b"ablePt", st)
    if i < 0:
        break
    offs.append(i)
    st = i + 1
f.write("  offsets: %s\n" % [hex(o) for o in offs])
for o in offs:
    # show context
    ctx = raw[max(0, o - 40):o + 60].decode("latin1")
    f.write("  0x%X ctx=%r\n" % (o, ctx))

# find VAs of those strings and search for push imm32 in .text
f.write("\n  code references (push imm32 of string VA):\n")
for o in offs:
    sva = None
    for nm, va, vs, rp, rs in secs:
        if rp <= o < rp + rs:
            sva = IB + va + (o - rp)
    if sva is None:
        continue
    imm = struct.pack("<I", sva)
    refs = []
    st2 = 0
    while True:
        i2 = text.find(imm, st2)
        if i2 < 0:
            break
        refs.append(IB + tva + i2)
        st2 = i2 + 1
    f.write("    VA 0x%X -> %s\n" % (sva, [hex(r) for r in refs]))

# ---- (b) disassemble the type1=132 handler properly ----
f.write("\n\n### (b) type1=132 handler full disassembly @0x4185E5\n")
off = trp + (0x4185E5 - IB - tva)
code = raw[off:off + 0x180]
pos = 0
while pos < len(code):
    got = list(md.disasm(code[pos:pos + 15], 0x4185E5 + pos, count=1))
    if not got:
        f.write("0x%08X  db 0x%02X\n" % (0x4185E5 + pos, code[pos]))
        pos += 1
        continue
    ins = got[0]
    f.write("0x%08X  %-22s %s %s\n" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    pos += ins.size

# ---- (c) the attribute-name table lookup helper 0x426240 ----
f.write("\n\n### (c) helper 0x426240 disassembly (attribute lookup for type1=132)\n")
off = trp + (0x426240 - IB - tva)
code = raw[off:off + 0x120]
pos = 0
while pos < len(code):
    got = list(md.disasm(code[pos:pos + 15], 0x426240 + pos, count=1))
    if not got:
        f.write("0x%08X  db 0x%02X\n" % (0x426240 + pos, code[pos]))
        pos += 1
        continue
    ins = got[0]
    f.write("0x%08X  %-22s %s %s\n" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    pos += ins.size

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("ok")
