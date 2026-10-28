import io, sys, os, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
OUT = r"D:\XiuXian\_analysis\re\out"

def utf16_all(data, minlen=3):
    """All NUL-terminated UTF-16LE strings (ASCII or CJK), even-aligned."""
    out=[]; n=len(data); i=0
    while i+1 < n:
        cp = data[i] | (data[i+1]<<8)
        if (0x20 <= cp < 0x7F) or (0x4E00<=cp<=0x9FFF) or (0x3000<=cp<=0x303F) \
           or (0xFF00<=cp<=0xFFEF) or cp in (0x2018,0x2019,0x201C,0x201D,0x2026,0x2014,0xB7,0xA0):
            start=i; chars=[]
            while i+1 < n:
                c2 = data[i] | (data[i+1]<<8)
                if (0x20 <= c2 < 0x7F) or (0x4E00<=c2<=0x9FFF) or (0x3000<=c2<=0x303F) \
                   or (0xFF00<=c2<=0xFFEF) or c2 in (0x2018,0x2019,0x201C,0x201D,0x2026,0x2014,0xB7,0xA0):
                    chars.append(c2); i+=2
                else: break
            if i+1 < n and data[i]==0 and data[i+1]==0 and len(chars)>=minlen:
                out.append((start, ''.join(chr(c) for c in chars)))
            i+=2
        else:
            i+=2
    return out

if __name__ == '__main__':
    u = utf16_all(d, 3)
    with open(os.path.join(OUT,'utf16_all_strings.txt'),'w',encoding='utf-8') as f:
        for off,s in u:
            f.write('0x%06X\t0x%06X\t%s\n' % (off, p.off2rva(off) or 0, s))
    print('total utf16 strings:', len(u))
    # the .gjd schema-name region
    print()
    print('=== region 0x280D40-0x281400 (data file names + schema field names) ===')
    for off,s in u:
        if 0x280D40 <= off < 0x281400:
            print('  0x%06X  %s' % (off, s))
