# -*- coding: utf-8 -*-
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

TEXT_LO, TEXT_HI = 0x401000, 0x644800
trp, tva, trs = pe.text()
code = pe.raw[trp:trp+trs]
T = IMAGE_BASE + tva

W("=== A) arrays of >=10 consecutive .text pointers in .rdata/.data ===")
for s in pe.sections:
    if s["name"] not in (".rdata", ".data"):
        continue
    base = IMAGE_BASE + s["va"]
    n = s["rawsize"]//4
    run = []
    for i in range(n):
        va = base + i*4
        v = pe.u32(va)
        if v is not None and TEXT_LO <= v < TEXT_HI:
            run.append((va, v))
        else:
            if len(run) >= 10:
                W("  table at 0x%08X  len=%d" % (run[0][0], len(run)))
                W("      %s" % " ".join("0x%X" % x[1] for x in run[:40]))
                if len(run) > 40:
                    W("      ... %s" % " ".join("0x%X" % x[1] for x in run[40:80]))
            run = []
    if len(run) >= 10:
        W("  table at 0x%08X  len=%d" % (run[0][0], len(run)))
        W("      %s" % " ".join("0x%X" % x[1] for x in run))

W("")
W("=== B) all `83 /r ib` with mod=3 and ib==0x64, and nearby indirect jump ===")
hits = []
for i in range(len(code)-4):
    if code[i] != 0x83:
        continue
    m = code[i+1]
    if (m & 0xC0) != 0xC0:
        continue
    if code[i+2] != 0x64:
        continue
    hits.append((T+i, (m >> 3) & 7, m & 7))
for va, reg, rm in hits:
    near = []
    for ins in disasm(pe, va, 0x40):
        if ins[2] == "jmp" and "[" in ins[3] and "*4" in ins[3]:
            near.append(hex(ins[0]))
        if ins[0] > va + 0x30:
            break
    W("  0x%08X reg=%d rm=%d  near_indirect_jmp=%s" % (va, reg, rm, near))

W("")
W("=== C) `mov reg,[reg*4+disp32]` jump-table idiom (8B 04/0C/14/1C/24/2C/34/3C 85) ===")
for i in range(len(code)-8):
    if code[i] != 0x8B:
        continue
    if code[i+1] not in (0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C):
        continue
    if code[i+2] != 0x85:
        continue
    disp = struct.unpack_from("<I", code, i+3)[0]
    if not (0x400000 <= disp <= 0x700000):
        continue
    # read table
    ents = []
    for k in range(80):
        v = pe.u32(disp + k*4)
        if v is None or not (TEXT_LO <= v < TEXT_HI):
            break
        ents.append(v)
    if len(ents) >= 8:
        W("  site 0x%08X  table 0x%08X n=%d reg=%d" % (T+i, disp, len(ents), code[i+1] >> 3))
        W("      %s" % " ".join("0x%X" % v for v in ents[:40]))

W("")
W("=== D) data at 0x649CD0, 0x68D268, 0x68D290, 0x67914C, 0x68D278 ===")
for v in (0x649CD0, 0x649CE8, 0x649D00, 0x68D268, 0x68D278, 0x68D290, 0x67914C, 0x679164, 0x68D2E4):
    W("  0x%08X bytes: %s" % (v, pe.bytes_at(v, 32).hex()))
    W("       as cstr: %r  as wide: %r" % (pe.cstr(v, 40), pe.wide(v, 40)))

open(r"D:\XiuXian\_analysis\re\s13_tables.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
