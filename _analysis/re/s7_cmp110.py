# -*- coding: utf-8 -*-
"""Find sites comparing a memory operand against 110 (0x6E) and 132 (0x84).
Also find all `sub reg, 0x64` (type1-100 style) followed by an indirect jump."""
import sys, io, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

CMP8 = {0x85:"eax",0x8d:"ecx",0x95:"edx",0x9d:"ebx",0xb5:"esi",0xbd:"edi",
        0x45:"eax",0x4d:"ecx",0x55:"edx",0x5d:"ebx",0x75:"esi",0x7d:"edi"}
CMP32 = {0x85:"eax",0x8d:"ecx",0x95:"edx",0x9d:"ebx",0xb5:"esi",0xbd:"edi"}

trp, tva, trs = pe.text()
T = IMAGE_BASE + tva

def scan_cmp_mem_imm(imm):
    """return list of (site_va, text_desc)"""
    res = []
    for i in range(len(pe.raw)-tva-trs-12):
        pass
    return res

hits110 = []
hits132 = []
code = pe.raw[trp:trp+trs]
for i in range(len(code)-11):
    b0, b1 = code[i], code[i+1]
    # 83 /7 ib   -> cmp dword ptr [reg+disp8], imm8
    if b0 == 0x83 and (b1 & 0xC0) == 0x80 and (b1 & 0x38) == 0x38:
        mod = (b1 >> 6) & 3
        rm = b1 & 7
        if mod == 1:
            disp = struct.unpack_from("<b", code, i+2)[0]
            imm = code[i+3]
            va = T + i
            if imm == 0x6E: hits110.append((va, rm, disp))
            if imm == 0x84: hits132.append((va, rm, disp))
        elif mod == 2:
            disp = struct.unpack_from("<i", code, i+2)[0]
            imm = code[i+6]
            va = T + i
            if imm == 0x6E: hits110.append((va, rm, disp))
            if imm == 0x84: hits132.append((va, rm, disp))
        elif mod == 0 and rm == 5:
            disp = struct.unpack_from("<i", code, i+2)[0]
            imm = code[i+6]
            va = T + i
            if imm == 0x6E: hits110.append((va, rm, disp))
            if imm == 0x84: hits132.append((va, rm, disp))
    # 81 /7 id -> cmp dword ptr [reg+disp], imm32
    if b0 == 0x81 and (b1 & 0xC0) == 0x80 and (b1 & 0x38) == 0x38:
        mod = (b1 >> 6) & 3
        rm = b1 & 7
        if mod == 1:
            disp = struct.unpack_from("<b", code, i+2)[0]
            imm = struct.unpack_from("<I", code, i+3)[0]
            va = T + i
            if imm == 0x6E: hits110.append((va, rm, disp))
            if imm == 0x84: hits132.append((va, rm, disp))
        elif mod == 2:
            disp = struct.unpack_from("<i", code, i+2)[0]
            imm = struct.unpack_from("<I", code, i+6)[0]
            va = T + i
            if imm == 0x6E: hits110.append((va, rm, disp))
            if imm == 0x84: hits132.append((va, rm, disp))

W("=== cmp dword ptr [reg+disp], 110 (0x6E): %d sites ===" % len(hits110))
for va, rm, disp in hits110:
    W("  0x%08X  [%s+0x%X]" % (va, {0:"eax",1:"ecx",2:"edx",3:"ebx",6:"esi",7:"edi"}.get(rm,"r%d"%rm), disp & 0xFFFFFFFF))

W("\n=== cmp dword ptr [reg+disp], 132 (0x84): %d sites ===" % len(hits132))
for va, rm, disp in hits132:
    W("  0x%08X  [%s+0x%X]" % (va, {0:"eax",1:"ecx",2:"edx",3:"ebx",6:"esi",7:"edi"}.get(rm,"r%d"%rm), disp & 0xFFFFFFFF))

# sub reg,0x64 sites
W("\n=== sub reg,0x64 (type1-100) sites ===")
subs = []
for i in range(len(code)-4):
    if code[i] == 0x83 and (code[i+1] & 0xF8) in (0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF):
        if code[i+2] == 0x64:
            subs.append(T+i)
for s in subs:
    W("  0x%08X" % s)
W("  total %d" % len(subs))
for s in subs:
    W("\n--- context around 0x%08X ---" % s)
    for ins in disasm(pe, s-0x30, 0x60):
        W("  0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))

open(r"D:\XiuXian\_analysis\re\s7_cmp110.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
