import io, sys, os, struct, importlib, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
import x86len; importlib.reload(x86len)
from x86len import insn_len, modrm_extent
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def rva(o): return o-TS+TEXT['vaddr']

# ---- decode .text function by function ----
starts=[]; i=TS
while i<TE-1:
    if d[i]==0xCC:
        j=i
        while j<TE and d[j]==0xCC: j+=1
        if j-i>=2 and j<TE: starts.append(j)
        i=j
    else: i+=1
starts=sorted(set(starts+[TS]))

FUNCS=[]      # (start, end, [insn offsets])
cmps=[]       # (offset, funcstart, kind, imm)
for k,st in enumerate(starts):
    end = starts[k+1] if k+1<len(starts) else TE
    o=st; offs=[]; ok=True
    while o<end:
        L=insn_len(d,o)
        if L==0 or o+L>end:
            ok=False; break
        offs.append((o,L)); o+=L
    if not ok: continue
    FUNCS.append((st,end,[x[0] for x in offs]))
    for (o,L) in offs:
        raw=d[o:o+L]
        # skip prefixes
        kk=0
        while kk<L and raw[kk] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): kk+=1
        if kk>=L: continue
        op=raw[kk]
        try:
            if op==0x83 and ((raw[kk+1]>>3)&7)==7 and kk+3<=L:
                cmps.append((o, st, 'r/m32,imm8', struct.unpack_from('<b',raw,kk+2)[0] & 0xFFFFFFFF))
            elif op==0x81 and ((raw[kk+1]>>3)&7)==7:
                e=modrm_extent(raw,kk+1)
                if kk+1+e+4<=L:
                    cmps.append((o, st, 'r/m32,imm32', struct.unpack_from('<I',raw,kk+1+e)[0]))
            elif op==0x3D and kk+5<=L:
                cmps.append((o, st, 'eax,imm32', struct.unpack_from('<I',raw,kk+1)[0]))
        except Exception: pass

print('valid functions: %d   cmp instructions decoded: %d' % (len(FUNCS), len(cmps)))

byval=collections.defaultdict(set)
for o,f,kind,imm in cmps: byval[imm].add(f)

ITEMS = [100,105,106,107,108,110,112,113,114,115,116,117,118,119,120,121,122,123,124,126,127,128,129,130,131,132,200,201,202,203,204,300,302,303]
print()
print('=== item-type constant presence among DECODED cmp instructions ===')
for t in ITEMS:
    fs = byval.get(t,set())
    print('   type1=%-4d  cmp sites=%-3d  in %d distinct functions  %s' % (
        t, sum(1 for o,f,k,im in cmps if im==t), len(fs),
        sorted('0x%06X'%f for f in fs)[:6]))

print()
print('=== functions containing the most item-type constants ===')
score=collections.Counter()
for o,f,kind,imm in cmps:
    if imm in ITEMS: score[f]+=1
for f,c in score.most_common(12):
    consts = sorted(set(im for o,ff,k,im in cmps if ff==f and im in ITEMS))
    fe = next(e for s,e,o in FUNCS if s==f)
    print('  FUNC 0x%06X-0x%06X (rva 0x%06X) size=%-6d distinct item consts=%d  %s' % (
        f, fe, rva(f), fe-f, len(consts), consts))

# save
with open(r"D:\XiuXian\_analysis\re\out\cmp_itemtypes.txt",'w',encoding='utf-8') as fh:
    for o,f,kind,imm in sorted(cmps):
        if imm in ITEMS: fh.write('0x%06X\t0x%06X\t%s\t%d\n'%(o,f,kind,imm))
print()
print('analysis of type1 129/130/132 among decoded cmps:')
for t in (129,130,132):
    hits=[(o,f) for o,f,k,im in cmps if im==t]
    print('   %d -> %d decoded cmp sites %s' % (t, len(hits), [('0x%06X'%o,'func 0x%06X'%f) for o,f in hits[:8]]))
