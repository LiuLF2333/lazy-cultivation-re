import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE

pe = PE(r"D:\XiuXian\懒人修仙传.exe.bak.20261019-193436-571623")
start = 0x68E000
end = 0x68F400
off = pe.va2off(start)
raw = pe.raw
i = off
cur = start
while cur < end:
    j = i
    chars = []
    while j + 1 < len(raw):
        cp = raw[j] | (raw[j + 1] << 8)
        if cp == 0 or not (32 <= cp < 0xD800 or 0x4E00 <= cp <= 0x9FFF):
            break
        chars.append(cp)
        j += 2
    if len(chars) >= 2:
        s = bytes(b for cp in chars for b in (cp & 0xFF, cp >> 8)).decode("utf-16-le", "replace")
        print("0x%08X %r" % (cur, s))
        i = j + 2
        cur = pe.off2va(i) or (cur + (i - (pe.va2off(cur) or i)))
    else:
        i += 2
        cur += 2
