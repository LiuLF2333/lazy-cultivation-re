import io, sys, os, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data

def dump_region(a, b, title):
    print('='*78); print('### %s  file 0x%X-0x%X  (rva 0x%X)' % (title, a, b, p.off2rva(a) or 0))
    i = a
    while i < b:
        # find next NUL-terminated UTF-16 run
        if d[i] == 0 and d[i+1] == 0:
            i += 2; continue
        j = i; chars = []
        while j+1 < b and not (d[j]==0 and d[j+1]==0):
            chars.append(d[j] | (d[j+1]<<8)); j += 2
        if chars:
            s = ''.join(chr(c) if c >= 0x20 else '.' for c in chars)
            if any(0x4e00 <= c <= 0x9fff for c in chars) or any(0x20 <= c < 0x7f for c in chars):
                print('  0x%06X  %s' % (i, s[:110]))
        i = j + 2

dump_region(0x28EA00, 0x28ED00, 'MOD / config region')
dump_region(0x290F00, 0x291300, 'MOD region 2')
dump_region(0x291300, 0x291450, 'MOD region 3')
dump_region(0x280D00, 0x281300, 'Data/.gjd load region')
