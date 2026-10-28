# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

def wstr(va, maxb=0x400):
    b = pe.bytes_at(va, maxb)
    z = b.find(b"\x00\x00")
    if z >= 0: b = b[:z+1]
    if len(b) % 2: b += b"\x00"
    return b.decode("utf-16-le", "replace")

W("### 0x418F50 .. 0x419600 : pushes of string immediates ###")
seen = set()
for ins in disasm(pe, 0x418F50, 0x6B0):
    if ins[2] == "push" and ins[3].startswith("0x68"):
        va = int(ins[3], 16)
        if 0x670000 <= va <= 0x6D0000:
            s = wstr(va)
            if s not in seen:
                seen.add(s)
                W("   0x%08X push 0x%08X  %r" % (ins[0], va, s[:90]))
W("")
W("### full 0x418F50 disasm (first 0x180) ###")
for ins in disasm(pe, 0x418F50, 0x180):
    W("0x%08X off=0x%06X %-22s %s %s" % (ins[0], pe.va2off(ins[0]), ins[1].hex(), ins[2], ins[3]))
W("")
W("### struct offsets 0x280..0x2A0 read/written in 0x439xxx..0x43Axxx ###")
for ins in disasm(pe, 0x439000, 0x1600):
    if "0x2" in ins[3] and "ptr [" in ins[3]:
        for off in ("0x280", "0x284", "0x288", "0x28c", "0x290", "0x294", "0x298", "0x29c", "0x278", "0x27c", "0x268", "0x26c", "0x264", "0x25c"):
            if ("+ %s]" % off) in ins[3]:
                W("   0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
                break
open(r"D:\XiuXian\_analysis\re\s52_fmt.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
