# -*- coding: utf-8 -*-
"""Find all timing-related API call sites and nearby context."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p = PE(r"D:\XiuXian\懒人修仙传.exe")
d = p.raw
TEXT = next(s for s in p.sections if s["name"] == ".text")
TS, TE = TEXT["rawptr"], TEXT["rawptr"] + TEXT["rawsize"]
md = Cs(CS_ARCH_X86, CS_MODE_32)

IAT = {
    0x0064541C: "Sleep",
    0x006457E0: "SetTimer",
    0x006457FC: "KillTimer",
    0x00645920: "timeGetTime",
    0x00645408: "GetTickCount",
    0x00645264: "QueryPerformanceCounter",
    0x00645204: "QueryPerformanceFrequency",
}

def callsites(iat):
    pat = b"\xFF\x15" + struct.pack("<I", iat)
    out = []
    i = TS
    while True:
        i = d.find(pat, i, TE)
        if i < 0:
            break
        out.append(i)
        i += 1
    return out

def show(off, before=28, after=12):
    start = max(TS, off - before)
    va = p.off2va(start)
    code = d[start:off + after]
    print("  --- file 0x%06X va 0x%08X ---" % (off, p.off2va(off)))
    for ins in md.disasm(code, va):
        mark = " <<<" if ins.address <= p.off2va(off) < ins.address + ins.size else ""
        print("    %08X  %-24s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))

for iat, name in IAT.items():
    sites = callsites(iat)
    print("%s : %d sites" % (name, len(sites)))
    for off in sites:
        show(off)
    print()
