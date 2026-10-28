import io, sys, os, struct, collections, importlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
import x86len; importlib.reload(x86len)
from x86len import insn_len
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def rva(o): return o-TS+TEXT['vaddr']

# ---------- A. comprehensive cmp-immediate scan (all encodings of cmp r/m32,imm) ----------
print('=== comparisons against item-type codes, ALL encodings ===')
TARGETS = list(range(100,136)) + list(range(200,205)) + list(range(300,305)) + [999, 1000]
res = collections.defaultdict(list)
i = TS
while i < TE-6:
    op = d[i]
    # 83 /7 ib  -> cmp r/m32, imm8   (signed byte: -128..127)
    if op == 0x83:
        modrm = d[i+1]; reg=(modrm>>3)&7
        if reg == 7:
            imm = struct.unpack_from('<b', d, i+2)[0] & 0xFFFFFFFF
            if imm in TARGETS: res[imm].append((i,'83 /7 ib',d[i:i+3]))
        i += 2 + (1 if (modrm>>6)==3 else 1) - 1 + 1
    # 81 /7 id  -> cmp r/m32, imm32
    elif op == 0x81:
        modrm = d[i+1]; reg=(modrm>>3)&7
        if reg == 7:
            # need modrm length; use decoder helper
            from x86len import modrm_extent
            e = modrm_extent(d, i+1)
            if i+1+e+4 <= TE:
                imm = struct.unpack_from('<I', d, i+1+e)[0]
                if imm in TARGETS: res[imm].append((i,'81 /7 id',d[i:i+1+e+4]))
        i += 1
    # 3D id -> cmp eax, imm32
    elif op == 0x3D:
        imm = struct.unpack_from('<I', d, i+1)[0]
        if imm in TARGETS: res[imm].append((i,'3D id',d[i:i+5]))
        i += 1
    else:
        i += 1

for t in sorted(res):
    sites = res[t]
    print('  cmp ...,%-5d (%3d) : %d sites  %s' % (t,t,len(sites), [('0x%06X'%s[0]) for s in sites[:10]]))

print()
print('=== which of 100..135 / 200..204 / 300..304 are NEVER compared? ===')
never = [t for t in TARGETS if t not in res and t < 400]
print('  ', never)

# ---------- B. characterize the shared selection helpers ----------
def walk(start, n=45):
    o=start; out=[]
    for _ in range(n):
        if o>=TE: break
        L=insn_len(d,o)
        if L==0: break
        out.append((o,L,d[o:o+L])); o+=L
    return out

for target in (0x020AB0, 0x020B30, 0x009A20):
    print()
    print('='*78)
    print('### shared selection helper 0x%06X (rva 0x%06X) - first instructions' % (target, rva(target)))
    for (o,L,raw) in walk(target, 16):
        print('  0x%06X  %s' % (o, ' '.join('%02X'%b for b in raw)))

# ---------- C. distance from prompt to the 3 calls, to see the idiom shape ----------
print()
print('='*78)
print('### idiom shape: bytes between prompt push and the 3 shared calls')
def ctx(site, n=40):
    return walk(site, n)
for site in (0x09F276, 0x0AD891, 0x0B3DDC):
    print('-'*60); print('prompt @0x%06X' % site)
    for (o,L,raw) in ctx(site, 22):
        mark=''
        if L==5 and raw[0]==0xE8:
            t=o+5+struct.unpack_from('<i',d,o+1)[0]
            mark='  -> 0x%06X' % t
            if t in (0x020AB0,0x020B30,0x009A20): mark += '  [SHARED]'
        print('   0x%06X  %-26s%s' % (o, ' '.join('%02X'%b for b in raw[:10]), mark))
