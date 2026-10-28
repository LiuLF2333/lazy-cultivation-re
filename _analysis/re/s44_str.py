# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

def dec(va, maxlen=0x200):
    b = pe.bytes_at(va, maxlen)
    z = b.find(b"\x00\x00")
    if z >= 0:
        b = b[:z+1]
    res = {}
    for nm, bb in (("raw", b),
                   ("swap", bytes(b"".join(bytes([b[i+1], b[i]]) for i in range(0, len(b)-1, 2)) + b[len(b)//2*2:]))):
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                res[nm+"/"+enc] = bb.decode(enc, "replace")
            except Exception as e:
                res[nm+"/"+enc] = "ERR"
    return res

for va in (0x6812B0, 0x6812FC, 0x681380, 0x681400, 0x6814C4, 0x6815C4, 0x6816FC, 0x681734, 0x68176C):
    W("### 0x%08X" % va)
    d = dec(va)
    for k, v in d.items():
        # pick the one with CJK
        W("   %-16s %r" % (k, v[:60]))
    W("")

W("### callers of 0x4183B0 ###")
for c in pe.find_calls_to(0x4183B0):
    W("  site 0x%08X off=0x%06X" % (c, pe.va2off(c)))
    for ins in disasm(pe, c-0x40, 0x40):
        W("     0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
    W("")
open(r"D:\XiuXian\_analysis\re\s44_str.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
