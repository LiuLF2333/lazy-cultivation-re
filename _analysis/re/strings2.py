import sys, re, io, struct, collections, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH, entropy

OUT = r"D:\XiuXian\_analysis\re\out"
os.makedirs(OUT, exist_ok=True)
p = PE(PATH); d = p.data

def sec_of(off):
    for s in p.sections:
        if s['rawptr'] <= off < s['rawptr']+s['rawsize']:
            return s['name']
    return '?'

def rva(off):
    r = p.off2rva(off)
    return r

# ---- ASCII ----
def ascii_strings(data, minlen=5):
    out=[]; cur=bytearray(); start=0
    for i,b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur: start=i
            cur.append(b)
        else:
            if len(cur)>=minlen: out.append((start, cur.decode('latin1')))
            cur=bytearray()
    if len(cur)>=minlen: out.append((start,cur.decode('latin1')))
    return out

# ---- UTF-16LE : strict CJK runs, even alignment, NUL-terminated ----
CJK = lambda cp: (0x4E00 <= cp <= 0x9FFF) or (0x3400<=cp<=0x4DBF) or (0xF900<=cp<=0xFAFF)
PUNCT = {0x3001,0x3002,0xFF01,0xFF08,0xFF09,0xFF0C,0xFF1A,0xFF1B,0xFF1F,0x2018,0x2019,
         0x201C,0x201D,0x2026,0x2014,0x00B7,0x300A,0x300B,0xFF5E,0x3010,0x3011,0xFF1D,0xFF0B,
         0x2192,0x2605,0x2606,0x25CF,0x25A0,0x3014,0x3015}
def utf16_cjk(data, minlen=2):
    """Find NUL-terminated UTF-16LE runs containing >=minlen CJK chars."""
    out=[]; n=len(data); i=0
    while i+1 < n:
        cp = data[i] | (data[i+1]<<8)
        if CJK(cp) or cp in PUNCT:
            start=i; chars=[]
            while i+1 < n:
                c2 = data[i] | (data[i+1]<<8)
                if CJK(c2) or c2 in PUNCT or (0x20<=c2<0x7F) or (0xFF10<=c2<=0xFF19) or (0xFF21<=c2<=0xFF3A) or (0xFF41<=c2<=0xFF5A):
                    chars.append(c2); i+=2
                else: break
            ncn = sum(1 for c in chars if CJK(c))
            # must be terminated by 00 00
            term = (i+1 < n and data[i]==0 and data[i+1]==0)
            if ncn >= minlen and term:
                out.append((start, ''.join(chr(c) for c in chars)))
        else:
            i+=2
    return out

# ---- XOR keyword scan ----
KEYWORDS = ['选择','请选择','属性','根骨','机缘','悟性','确定','取消','随机','自选','列表',
            '下拉','请选择属性','选择属性','增加属性','属性选择','Select','Attribute']
def xor_scan(data, keywords):
    hits = collections.defaultdict(list)
    for kw in keywords:
        try: kb = kw.encode('gbk')
        except Exception: continue
        for K in range(256):
            pat = bytes(b ^ K for b in kb)
            s=0
            while True:
                j = data.find(pat,s)
                if j<0: break
                hits[K].append((kw,j)); s=j+1
    return hits

if __name__ == '__main__':
    with open(os.path.join(OUT,'ascii_strings.txt'),'w',encoding='utf-8') as f:
        for off,s in ascii_strings(d,5):
            f.write('0x%06X\t0x%06X\t%s\t%s\n' % (off, rva(off) or 0, sec_of(off), s))
    u = utf16_cjk(d,2)
    with open(os.path.join(OUT,'utf16_cjk_strings.txt'),'w',encoding='utf-8') as f:
        for off,s in u:
            f.write('0x%06X\t0x%06X\t%s\t%s\n' % (off, rva(off) or 0, sec_of(off), s))
    print('ascii>=5 :', len(ascii_strings(d,5)))
    print('utf16cjk :', len(u))

    with open(os.path.join(OUT,'xor_keyword_hits.txt'),'w',encoding='utf-8') as f:
        hits = xor_scan(d, KEYWORDS)
        for K in sorted(hits, key=lambda k:-len(hits[k])):
            if not hits[K]: continue
            line = 'KEY 0x%02X (%3d) : %d hits\n' % (K,K,len(hits[K]))
            f.write(line); print(line.rstrip())
            for kw,o in hits[K][:30]:
                f.write('     %-12s off=0x%06X rva=0x%06X sec=%s\n' % (kw,o,rva(o) or 0,sec_of(o)))
                print('     %-12s off=0x%06X rva=0x%06X sec=%s' % (kw,o,rva(o) or 0,sec_of(o)))
    print('done')
