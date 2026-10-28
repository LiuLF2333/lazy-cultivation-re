# -*- coding: utf-8 -*-
import sys, io
from collections import Counter
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm
pe = PE()
out = io.StringIO()
def W(s=""):
    out.write(s + "\n")
for tgt, tag in ((0x439680, "int getter"), (0x4396f0, "str getter"), (0x438920, "find-key")):
    W("=== %s 0x%08X ===" % (tag, tgt))
    cnt = Counter()
    for c in pe.find_calls_to(tgt):
        base = None
        for ins in disasm(pe, c-0x24, 0x24):
            if ins[0] == c: break
            if ins[2] == "add" and ins[3].startswith("ecx,") and "0x" in ins[3]:
                base = ins[3]
            if ins[2] == "lea" and ins[3].startswith("ecx, ["):
                base = "LEA " + ins[3]
        cnt[base] += 1
        W("  0x%08X  base=%s" % (c, base))
    W("  summary:")
    for k, v in cnt.most_common():
        W("    %-28s %d" % (k, v))
    W("")
open(r"D:\XiuXian\_analysis\re\s33b.txt", "w", encoding="utf-8").write(out.getvalue())
print("ok")
