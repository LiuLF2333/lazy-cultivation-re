# -*- coding: utf-8 -*-
"""Enumerate all switch jump tables `jmp dword ptr [reg*4+disp32]` and
`call dword ptr [reg*4+disp32]` in .text; report tables whose entries
land in .text."""
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

W("sections:")
for s in pe.sections:
    W("  %-8s VA 0x%-8X vsize 0x%-8X rawptr 0x%-8X rawsize 0x%-8X chars 0x%X"
      % (s["name"], IMAGE_BASE+s["va"], s["vsize"], s["rawptr"], s["rawsize"], s["chars"]))

trp, tva, trs = pe.text()
text = pe.raw[trp:trp+trs]
W("\n.text VA 0x%X .. 0x%X" % (IMAGE_BASE+tva, IMAGE_BASE+tva+trs))

SIB = {0x85:"eax",0x8d:"ecx",0x95:"edx",0x9d:"ebx",0xa5:"esp",0xad:"ebp",0xb5:"esi",0xbd:"edi"}
tables = []
for i in range(len(text)-10):
    if text[i] != 0xFF: continue
    if text[i+1] not in (0x24,): continue
    sib = text[i+2]
    if sib not in SIB: continue
    disp = struct.unpack_from("<I", text, i+3)[0]
    if disp < 0x400000 or disp > 0x800000: continue
    # this is `jmp dword ptr [reg*4+disp]`
    site = IMAGE_BASE + tva + i
    tables.append((site, SIB[sib], disp))

W("\nfound %d indirect [reg*4+disp32] sites" % len(tables))
for site, reg, disp in tables:
    # read up to 64 entries, stop when out of .text/.rdata
    ents = []
    for k in range(64):
        v = pe.u32(disp + k*4)
        if v is None or v < 0x401000 or v > 0x700000:
            break
        ents.append(v)
    if len(ents) < 5:
        continue
    tgt_in_text = sum(1 for v in ents if 0x401000 <= v < IMAGE_BASE+tva+trs)
    W("\n  site 0x%08X  [%s*4+0x%08X]  entries=%d  in_text=%d" % (site, reg, disp, len(ents), tgt_in_text))
    W("      entries: %s" % " ".join("0x%X" % v for v in ents[:40]))

open(r"D:\XiuXian\_analysis\re\s4_jumptables.txt","w",encoding="utf-8").write(out.getvalue())
print("ok", len(tables))
