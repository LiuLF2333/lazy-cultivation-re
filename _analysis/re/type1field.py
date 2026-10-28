import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def rva(o): return o-TS+TEXT['vaddr']

ITEMS=set([0,100,105,106,107,108,110,112,113,114,115,116,117,118,119,120,121,122,123,124,126,127,
           128,129,130,131,132,200,201,202,203,204,300,302,303])

print('### A. ItemTable category columns ###')
b=open(r"D:\XiuXian\_analysis\decoded\ItemTable.txt",'rb').read()
for enc in ('utf-8-sig','utf-8','gbk'):
    try: L=b.decode(enc).splitlines(); break
    except Exception: pass
hdr=L[0].split(',')
for col in (3,4,5,6,7):
    vals=collections.Counter()
    for l in L[1:]:
        c=l.split(',')
        if len(c)>col:
            try: vals[int(c[col])]+=1
            except Exception: pass
    print('  col%d %-8s distinct=%d  values=%s' % (col, hdr[col], len(vals), sorted(vals)[:40]))
# condition / judge columns
for col in (8,9):
    vals=collections.Counter()
    for l in L[1:]:
        c=l.split(',')
        if len(c)>col:
            try: vals[int(c[col])]+=1
            except Exception: pass
    print('  col%d %-8s distinct=%d  values=%s' % (col, hdr[col], len(vals), sorted(vals)[:40]))

print()
print('### B. every "cmp dword [reg+disp32], imm" in .text whose immediate is an item type ###')
hits=[]
i=TS
while i < TE-8:
    # 83 /7 with mod=10 (disp32): modrm = 0x7 | (reg<<3) | 0b10<<6 -> 0xB8..0xBF
    if d[i]==0x83 and 0xB8<=d[i+1]<=0xBF:
        disp=struct.unpack_from('<I',d,i+2)[0]
        imm=d[i+6]
        if imm in ITEMS: hits.append((i,'cmp [r+0x%X],%d'%(disp,imm),imm))
    # 81 /7 with mod=10
    if d[i]==0x81 and 0xB8<=d[i+1]<=0xBF:
        disp=struct.unpack_from('<I',d,i+2)[0]
        imm=struct.unpack_from('<I',d,i+6)[0]
        if imm in ITEMS: hits.append((i,'cmp [r+0x%X],%d'%(disp,imm),imm))
    i+=1
print('count:', len(hits))
byoff=collections.defaultdict(set)
for o,desc,imm in hits: byoff[desc.split('],')[0]+']'].add(imm)
for o,desc,imm in sorted(hits, key=lambda x:x[2]):
    print('   0x%06X (rva 0x%06X)  %-24s' % (o, rva(o), desc))

print()
print('### C. distinct switch fields (cmp [reg+disp32], imm8) grouped by displacement ###')
fields=collections.defaultdict(set)
i=TS
while i<TE-8:
    if d[i]==0x83 and 0xB8<=d[i+1]<=0xBF:
        disp=struct.unpack_from('<I',d,i+2)[0]
        if disp<0x1000: fields[disp].add(d[i+6])
    i+=1
for disp in sorted(fields):
    vs=sorted(fields[disp])
    if len(vs)>=6:
        print('  [obj+0x%03X] distinct=%d  values=%s' % (disp, len(vs), vs[:40]))
