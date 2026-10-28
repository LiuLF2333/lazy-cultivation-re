import io, sys, os, struct, re, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH

p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')

def file_is_text(off):
    return TEXT['rawptr'] <= off < TEXT['rawptr']+TEXT['rawsize']

# ---- absolute address -> file offset ----
def abs2off(addr):
    rva = addr - p.image_base
    return p.rva2off(rva)

# ---- collect candidate immediate operands that point at a target string ----
def xrefs_to(off, window_scan=True):
    """Find push imm32 / mov reg,imm32 occurrences whose value == VA of off,
       plus any raw dword equal to that VA anywhere."""
    va = p.off2rva(off)
    if va is None: return [], []
    target = va + p.image_base
    raw_hits = []
    start = 0
    pat = struct.pack('<I', target)
    while True:
        j = d.find(pat, start)
        if j < 0: break
        raw_hits.append(j)
        start = j+1
    code_hits = []
    for h in raw_hits:
        if file_is_text(h):
            # check preceding byte is 0x68 (push imm32)
            if h-1 >= 0 and d[h-1] == 0x68:
                code_hits.append((h-1, 'push imm32'))
            elif h-2 >= 0 and d[h-2] == 0xB8:
                code_hits.append((h-2, 'mov eax,imm32'))
            elif h-2 >= 0 and 0xB8 <= d[h-2] <= 0xBF:
                code_hits.append((h-2, 'mov r32,imm32'))
            else:
                code_hits.append((h, 'dword-in-code?'))
    return raw_hits, code_hits

# ---- the numeric column of GameAttribStringTable (internal attribute IDs) ----
DEC = r"D:\XiuXian\_analysis\decoded"
def rd(n):
    b = open(os.path.join(DEC,n),'rb').read()
    for enc in ('utf-8-sig','utf-8','gbk'):
        try: return b.decode(enc).splitlines()
        except Exception: pass
    return b.decode('gbk',errors='replace').splitlines()

G = rd('GameAttribStringTable.txt')
ids = []
for l in G[1:]:
    c = l.split(',')
    if len(c) >= 3:
        try: ids.append((int(c[1]), c[0], c[2]))
        except ValueError: pass
print('attribute internal IDs from table: %d  (min=%d max=%d)' % (len(ids), min(i[0] for i in ids), max(i[0] for i in ids)))
print('sample:', [(i,n) for i,n,t in ids[:8]])

# ---- find cross-references to each attribute ID as an immediate ----
print()
print('=== immediates 0..100 in .text, histogram, and which look like attribute IDs ===')
hist = collections.Counter()
# scan for push imm8 / push imm32 / mov r32,imm32 with small values
for i in range(TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']-5):
    b = d[i]
    if b == 0x6A:              # push imm8
        hist[d[i+1]] += 1
    elif b == 0x68:            # push imm32
        v = struct.unpack_from('<I', d, i+1)[0]
        if v < 0x10000: hist[v] += 1
    elif 0xB8 <= b <= 0xBF:    # mov r32, imm32
        v = struct.unpack_from('<I', d, i+1)[0]
        if v < 0x10000: hist[v] += 1
tabids = set(i[0] for i in ids)
top = [(v,c) for v,c in hist.most_common(400) if v in tabids]
print('most frequent immediates that ARE attribute IDs (value, count, name):')
idmap = {i[0]:i[1] for i in ids}
for v,c in top[:60]:
    print('   %4d  x%-5d  %s' % (v, c, idmap.get(v,'')))
