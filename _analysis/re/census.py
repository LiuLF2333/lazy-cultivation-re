import io, sys, os, struct, collections, importlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
import x86len; importlib.reload(x86len)
from x86len import insn_len, modrm_extent
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def rva(o): return o-TS+TEXT['vaddr']

# ---------- 1. ItemTable type1 census ----------
DEC=r"D:\XiuXian\_analysis\decoded"
b=open(os.path.join(DEC,'ItemTable.txt'),'rb').read()
for enc in ('utf-8-sig','utf-8','gbk'):
    try: L=b.decode(enc).splitlines(); break
    except Exception: pass
hdr=L[0].split(','); i1=hdr.index('type1')
census=collections.Counter(); names=collections.defaultdict(list)
for l in L[1:]:
    c=l.split(',')
    if len(c)<=i1: continue
    try: t=int(c[i1])
    except Exception: continue
    census[t]+=1
    if len(names[t])<3: names[t].append(c[1])
print('=== ItemTable type1 census (distinct=%d) ===' % len(census))
for t in sorted(census):
    print('   type1=%-4d count=%-3d  e.g. %s' % (t, census[t], ' / '.join(names[t])))

# ---------- 2. all cmp immediates in .text ----------
cmpset = set()
i=TS
while i < TE-6:
    op=d[i]
    if op==0x83:
        if ((d[i+1]>>3)&7)==7:
            cmpset.add(struct.unpack_from('<b',d,i+2)[0] & 0xFFFFFFFF)
    elif op==0x81:
        if ((d[i+1]>>3)&7)==7:
            e=modrm_extent(d,i+1)
            if i+1+e+4<=TE: cmpset.add(struct.unpack_from('<I',d,i+1+e)[0])
    elif op==0x3D:
        cmpset.add(struct.unpack_from('<I',d,i+1)[0])
    i+=1

print()
print('=== type1 values with ItemTable rows: implemented (compared somewhere) vs NOT ===')
present=set(census)
impl = sorted(t for t in present if t in cmpset)
notimpl = sorted(t for t in present if t not in cmpset)
print('  IMPLEMENTED (const appears in a cmp): %s' % impl)
print('  NOT COMPARED ANYWHERE:                %s' % notimpl)

# ---------- 3. disassemble the item-type dispatch cluster ----------
strs={}
for s in p.sections:
    a,bb=s['rawptr'],s['rawptr']+s['rawsize']; i=a
    while i<bb:
        j=i; ch=[]
        while j+1<bb:
            cp=d[j]|(d[j+1]<<8)
            if cp==0: break
            if (0x20<=cp<0x7f) or (0x4e00<=cp<=0x9fff) or (0x3000<=cp<=0x303f) or (0xff00<=cp<=0xffef) or cp in (0x2026,0x2014,0x2018,0x2019,0x201c,0x201d):
                ch.append(cp); j+=2
            else: ch=None; break
        if ch and len(ch)>=2 and j+1<bb and d[j]==0 and d[j+1]==0:
            r=p.off2rva(i)
            if r is not None: strs.setdefault(r+p.image_base,''.join(chr(c) for c in ch))
            i=j+2; continue
        j=i; ch=[]
        while j<bb and 0x20<=d[j]<0x7f: ch.append(chr(d[j])); j+=1
        if len(ch)>=4 and j<bb and d[j]==0:
            r=p.off2rva(i)
            if r is not None: strs.setdefault(r+p.image_base,''.join(ch))
            i=j+1; continue
        i+=1

def dis(start, end, title):
    print(); print('='*84); print('### %s   file 0x%X-0x%X (rva 0x%X-0x%X)'%(title,start,end,rva(start),rva(end)))
    o=start
    while o<end:
        L=insn_len(d,o)
        if L==0:
            print('  0x%06X  ??? %s' % (o, ' '.join('%02X'%x for x in d[o:o+8]))); o+=1; continue
        raw=d[o:o+L]; note=''
        # annotate cmp imm
        k=0
        while k<L and raw[k] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): k+=1
        if k<L:
            if raw[k]==0x83 and ((raw[k+1]>>3)&7)==7 and k+2<L:
                note='   ; cmp ...,%d' % (struct.unpack_from('<b',raw,k+2)[0] & 0xFFFFFFFF)
            elif raw[k]==0x81 and ((raw[k+1]>>3)&7)==7:
                e=modrm_extent(raw,k+1)
                if k+1+e+4<=L: note='   ; cmp ...,%d'%struct.unpack_from('<I',raw,k+1+e)[0]
            elif raw[k]==0x68 and k+5<=L:
                v=struct.unpack_from('<I',raw,k+1)[0]
                if v in strs: note='   ; "%s"'%strs[v][:64]
            elif raw[k]==0x6A and k+2<=L:
                note='   ; push %d'%(struct.unpack_from('<b',raw,k+1)[0] & 0xFFFFFFFF)
            elif raw[k]==0xE8 and k+5<=L:
                note='   ; call 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
        print('  0x%06X  %-30s%s' % (o, ' '.join('%02X'%x for x in raw[:14]), note))
        o+=L

dis(0x20A300, 0x20A800, 'ITEM-USE DISPATCH CLUSTER (part 1)')
