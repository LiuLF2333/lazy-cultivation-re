import sys, re, struct, collections
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH, entropy

p = PE(PATH); d = p.data

def gbk(s):
    return s.encode('gbk', errors='replace')

# ---------------- 1. Plain ASCII strings ----------------
def ascii_strings(data, minlen=5):
    out = []
    cur = bytearray(); start = 0
    for i,b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur: start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append((start, cur.decode('latin1')))
            cur = bytearray()
    if len(cur) >= minlen: out.append((start, cur.decode('latin1')))
    return out

# ---------------- 2. Plain UTF-16LE strings ----------------
def utf16_strings(data, minlen=4):
    out = []
    i = 0; n = len(data)
    cur = []; start = 0
    while i + 1 < n:
        lo, hi = data[i], data[i+1]
        cp = lo | (hi << 8)
        ok = (0x20 <= cp < 0x7F) or (0x4E00 <= cp <= 0x9FFF) or (0x3000 <= cp <= 0x303F) \
             or (0xFF00 <= cp <= 0xFFEF) or cp in (0x2018,0x2019,0x201C,0x201D,0x2026,0x2014,0xB7)
        if ok:
            if not cur: start = i
            cur.append(cp)
        else:
            if len(cur) >= minlen:
                out.append((start, ''.join(chr(c) for c in cur)))
            cur = []
        i += 2
    if len(cur) >= minlen: out.append((start, ''.join(chr(c) for c in cur)))
    return out

# ---------------- 3. Single-byte XOR keyword search ----------------
KEYWORDS = ['选择','请选择','属性','根骨','机缘','悟性','确定','取消','随机','请选择属性',
            '选择属性','添加属性','自选','自定义','列表','下拉','Select','Attribute']
def xor_keyword_scan(data, keywords, keys=range(256)):
    """For each key K, pattern = kw XOR K; find in original data. Equivalent to
       XORing whole file by K then searching for plain kw."""
    hits = collections.defaultdict(list)
    pats = {}
    for kw in keywords:
        for enc in ('gbk',):
            try: kb = gbk(kw)
            except Exception: continue
            for K in keys:
                pat = bytes(b ^ K for b in kb)
                pats[(kw, enc, K)] = pat
    for (kw, enc, K), pat in pats.items():
        start = 0
        while True:
            j = data.find(pat, start)
            if j < 0: break
            hits[K].append((kw, j))
            start = j + 1
    return hits

def valid_gbk(b):
    try:
        s = b.decode('gbk')
        return s
    except Exception:
        return None

if __name__ == '__main__':
    print('file size', len(d))
    a = ascii_strings(d, 5)
    print('ascii strings (>=5):', len(a))
    u = utf16_strings(d, 2)
    print('utf16 strings (>=2):', len(u))

    print('\n=== UTF-16LE Chinese-containing strings (sample) ===')
    cn = [x for x in u if any('\u4e00' <= c <= '\u9fff' for c in x[1])]
    print('count:', len(cn))
    for off, s in cn[:60]:
        print('  0x%06X  %s' % (off, s[:90]))

    print('\n=== XOR keyword scan (all 256 keys) ===')
    hits = xor_keyword_scan(d, KEYWORDS)
    for K in sorted(hits, key=lambda k: -len(hits[k])):
        v = hits[K]
        if not v: continue
        print('KEY 0x%02X : %d hits -> %s' % (K, len(v), [(w, hex(o)) for w,o in v[:14]]))
    if not hits:
        print('  no hits for any key')
