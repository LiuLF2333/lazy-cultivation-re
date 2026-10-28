import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def rva(o): return o-TS+TEXT['vaddr']
def va2off(v): return p.rva2off(v-p.image_base)
def off2va(o):
    r=p.off2rva(o); return None if r is None else r+p.image_base

def rd_utf16(off, n=64):
    out=[]
    for k in range(n):
        cp=d[off+2*k]|(d[off+2*k+1]<<8)
        if cp==0: break
        out.append(chr(cp))
    return ''.join(out)

print('### 1. verify string VAs')
for va in (0x6883F8, 0x688448, 0x6901EC, 0x690228, 0x69138C, 0x68ADAC, 0x68E960, 0x68E9CC,
           0x690794, 0x69145C, 0x68FFE4, 0x6907D4, 0x681180):
    o=va2off(va)
    print('   VA 0x%08X -> file 0x%06X rva 0x%06X : %r' % (va, o or 0, (o-TS+TEXT['vaddr']) if o else 0,
          rd_utf16(o) if o else 'N/A'))

print()
print('### 2. MOD path fragment xrefs (who builds Mods\\<name>\\Data and \\Res)')
for va,label in ((0x691354,'\\Res\\'), (0x691378,'\\Data\\'), (0x691360,'Mods\\'), (0x68EB1C,'ModConfig'),
                 (0x68EAE0,'SelMod'), (0x691344,'SelMod'), (0x68EABC,'config.ini')):
    sites=[]; s=TS
    pat=struct.pack('<I',va)
    while True:
        j=d.find(pat,s)
        if j<0: break
        if TS<=j<TE: sites.append(j)
        s=j+1
    ctx=''
    if sites:
        # show prose around first site
        a=max(TS,sites[0]-28)
        ctx=' '.join('%02X'%x for x in d[a:sites[0]+22])
    print('   %-12s VA=0x%08X file=0x%06X  xrefs in .text=%d %s' % (
        label, va, va2off(va) or 0, len(sites), [hex(x) for x in sites[:6]]))
    if ctx: print('        bytes around first xref (0x%06X): %s' % (max(TS,sites[0]-28), ctx))

print()
print('### 3. overlay / file-end check')
ends=[(s['name'], s['rawptr']+s['rawsize']) for s in p.sections]
mx=max(e for _,e in ends)
print('   section ends:', [('%s:0x%X'%e) for e in ends])
print('   max end = 0x%X ; file size = %d (0x%X) ; overlay bytes = %d' % (mx, len(d), len(d), len(d)-mx))
print('   CertTable (DD[4]) =', p.dd[4])
print('   CLR (DD[14])      =', p.dd[14])
print('   BoundImport DD[11]=', p.dd[11])

print()
print('### 4. CSV header names absent from EXE? (positional parsing test)')
for name in ['type1','value1','value2','ID','\u540d\u79f0','\u8bf4\u660e','\u54c1\u8d28']:
    a=d.count(name.encode('ascii',errors='ignore')) if name.isascii() else 0
    u=d.count(name.encode('utf-16-le'))
    g=0
    try: g=d.count(name.encode('gbk'))
    except Exception: pass
    print('   %-8s ascii=%-3d utf16=%-3d gbk=%-3d' % (name, a, u, g))

print()
print('### 5. CSV field delimiters used by the loader (UTF-16)')
for va,lab in ((0x680D6C,'"="'), (0x680D78,'","')):
    o=va2off(va)
    print('   %s VA=0x%08X file=0x%06X -> %r' % (lab, va, o or 0, rd_utf16(o,8) if o else 'N/A'))

print()
print('### 6. all 30 .gjd data-file names referenced (UTF-16)')
names=[]
for s in p.sections:
    a,b=s['rawptr'],s['rawptr']+s['rawsize']
    i=a
    while i<b:
        # find 'Data/' prefix
        if d[i:i+12]==b'D\x00a\x00t\x00a\x00/\x00':
            t=rd_utf16(i,64)
            if t.endswith('.gjd'): names.append((i,t))
            i+=12; continue
        i+=2
for o,t in names: print('   file 0x%06X rva 0x%06X  %s' % (o, rva(o), t))
print('   total:', len(names))

print()
print('### 7. item-use function type1 dispatch: compare-constants near each branch')
# the item-use function: find its start by locating push of 是否批量使用 string
site=None
s=TS; pat=b'\x68'+struct.pack('<I',0x6883F8)
while True:
    j=d.find(pat,s)
    if j<0: break
    if TS<=j<TE: site=j; break
    s=j+1
print('   batch-use prompt pushed at file 0x%06X (rva 0x%06X)' % (site, rva(site)))
# find enclosing function start
best=None
for k in range(max(TS,site-0x20000), site):
    if d[k]==0x55 and d[k+1]==0x8B and d[k+2]==0xEC and (k<TS+2 or d[k-1]==0xCC):
        # verify sequential decode
        from x86len import insn_len
        o=k; ok=True
        while o<site:
            L=insn_len(d,o)
            if L==0 or o+L>site: ok=False; break
            o+=L
        if ok: best=k
print('   enclosing function start = 0x%06X (rva 0x%06X)' % (best, rva(best)) if best else 'not found')
