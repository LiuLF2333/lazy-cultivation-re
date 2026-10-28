import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS, TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def off2va(o):
    r=p.off2rva(o); return None if r is None else r+p.image_base
def va2off(v): return p.rva2off(v-p.image_base)

# ---------- A. dialog resources: robust string scan ----------
rva,sz = p.dd[2]; base = p.rva2off(rva)
def read_dir(off, path, out):
    nname,nid = struct.unpack_from('<HH', d, off+12)
    for i in range(nname+nid):
        nid_or_name, dataoff = struct.unpack_from('<II', d, off+16+i*8)
        nm = nid_or_name
        if nid_or_name & 0x80000000:
            no = base+(nid_or_name & 0x7FFFFFFF); ln = struct.unpack_from('<H',d,no)[0]
            nm = d[no+2:no+2+ln*2].decode('utf-16-le',errors='replace')
        if dataoff & 0x80000000:
            read_dir(base+(dataoff & 0x7FFFFFFF), path+[nm], out)
        else:
            de = base+dataoff
            drva,dsz,cp,res = struct.unpack_from('<IIII',d,de)
            out.append((path+[nm], drva, dsz, cp, p.rva2off(drva)))
    return out
tree=[]; read_dir(base,[],tree)

def ustrings(seg):
    out=[]; i=0; n=len(seg)
    while i+1<n:
        cp = seg[i]|(seg[i+1]<<8)
        if 0x20<=cp<0x7f or 0x4e00<=cp<=0x9fff or 0x3000<=cp<=0x303f or 0xff00<=cp<=0xffef or cp in (0x2026,0x2018,0x2019,0x201c,0x201d,0x2014):
            s=[]
            while i+1<n:
                c2=seg[i]|(seg[i+1]<<8)
                if 0x20<=c2<0x7f or 0x4e00<=c2<=0x9fff or 0x3000<=c2<=0x303f or 0xff00<=c2<=0xffef or c2 in (0x2026,0x2018,0x2019,0x201c,0x201d,0x2014):
                    s.append(c2); i+=2
                else: break
            if len(s)>=2: out.append(''.join(chr(c) for c in s))
            i+=2
        else: i+=2
    return out

print('='*78)
print('=== DIALOG resources: identifying strings ===')
for path, drva, dsz, cp, off in tree:
    if path[0]!=5 or len(path)!=3: continue
    ss = ustrings(d[off:off+dsz])
    print('  dlg %-6s size=%-5d  %s' % (path[1], dsz, ' | '.join(ss[:14])))

# ---------- B. search for hardcoded item IDs and column names ----------
print()
print('='*78)
print('=== hardcoded item IDs 22365/22366 (type1=132 test items) ===')
for val in (22365,22366,22308,22309,22365-22000):
    pat = struct.pack('<I', val)
    hits=[]; s=0
    while True:
        j=d.find(pat,s)
        if j<0: break
        hits.append(j); s=j+1
    code=[h for h in hits if TS<=h<TE]
    print('  imm %-6d total=%-3d in .text=%s' % (val, len(hits), [hex(h) for h in code[:10]]))
    # push imm32 form
    for h in code[:10]:
        print('       @0x%06X context: %s' % (h-4, ' '.join('%02X'%b for b in d[max(0,h-8):h+8])))

# ---------- C. ItemTable column-name strings ----------
print()
print('='*78)
print('=== ItemTable column-name strings ("type1","value1",...) ===')
for name in ['type1','value1','type2','value2','\u4ece\u5206\u7c7b','\u6761\u4ef6\u503c']:
    for enc,label in ((name.encode('utf-16-le'),'utf16'),(name.encode('gbk'),'gbk'),(name.encode('ascii',errors='ignore'),'ascii')):
        if not enc: continue
        hits=[]; s=0
        while True:
            j=d.find(enc,s)
            if j<0: break
            hits.append(j); s=j+1
        if hits:
            print('  %-10s %-6s %d hits: %s' % (name, label, len(hits), [hex(h) for h in hits[:8]]))
