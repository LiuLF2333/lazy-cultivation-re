# -*- coding: utf-8 -*-
import sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")

p = r"D:\XiuXian\Data\ItemTable.gjd"
import os
W("exists=%s size=%d" % (os.path.exists(p), os.path.getsize(p) if os.path.exists(p) else -1))
raw = open(p, "rb").read()
W("first 64 raw bytes: %s" % raw[:64].hex())
dec = bytes(b ^ 0xC6 for b in raw[:1200])
W("")
W("XOR 0xC6 first 1200 bytes decoded as GBK:")
try:
    W(dec.decode("gbk", "replace"))
except Exception as e:
    W("ERR %s" % e)
W("")
W("--- decode function 0x60ec24 ---")
for ins in disasm(pe, 0x60EC24, 0xA0):
    W("0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
W("")
W("--- 0x60edde ---")
for ins in disasm(pe, 0x60EDDE, 0xA0):
    W("0x%08X %-22s %s %s" % (ins[0], ins[1].hex(), ins[2], ins[3]))
open(r"D:\XiuXian\_analysis\re\s49_raw.txt","w",encoding="utf-8").write(out.getvalue())
print("ok")
