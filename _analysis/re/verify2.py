import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def va2off(v): return p.rva2off(v-p.image_base)
def fo2rva(o): return p.off2rva(o)              # CORRECT for any section
def fo2va(o):
    r=p.off2rva(o); return None if r is None else r+p.image_base

def rd_utf16(off, n=80):
    out=[]
    for k in range(n):
        cp=d[off+2*k]|(d[off+2*k+1]<<8)
        if cp==0: break
        out.append(chr(cp))
    return ''.join(out)

print('### KEY STRINGS (VA / RVA / file offset) ###')
KEYS=[0x6883F8,0x688448,0x6901EC,0x690228,0x69138C,0x68ADAC,0x68E960,0x68E9CC,0x690794,
      0x69145C,0x68FFE4,0x6907D4,0x681180,0x6913A0,0x6913B8,0x6913CC,0x687BA4,0x68EB1C,
      0x68EAE0,0x691344,0x68EABC,0x691354,0x691378,0x691360,0x68EC18,0x691300,0x691018]
for va in KEYS:
    o=va2off(va)
    print('  VA 0x%08X  RVA 0x%08X  file 0x%06X  %r' % (va, va-p.image_base, o or 0, rd_utf16(o) if o else 'N/A'))

print()
print('### ALL .gjd filenames referenced (UTF-16 "Data/....gjd") ###')
names=[]; i=0
pat=b'D\x00a\x00t\x00a\x00/\x00'
while True:
    j=d.find(pat,i)
    if j<0: break
    t=rd_utf16(j,80)
    names.append((j,t)); i=j+2
for o,t in names:
    print('  file 0x%06X  RVA 0x%06X  VA 0x%08X  %s' % (o, fo2rva(o), fo2va(o), t))
print('  total:', len(names))

print()
print('### MOD loader: xrefs to "\\Data\\" and "\\Res\\" and "Mods\\" ###')
for va,lab in ((0x691378,'\\Data\\'),(0x691354,'\\Res\\'),(0x691360,'Mods\\'),(0x68EAE0,'SelMod@0x68EAE0'),
               (0x691344,'SelMod@0x691344'),(0x691388,'ModConfig@0x691388'),(0x691330,'ModConfig@0x691330'),
               (0x68EB1C,'ModConfig@0x68EB1C'),(0x680D4C,'Data/Config.gjd')):
    sites=[]; s=0; p4=struct.pack('<I',va)
    while True:
        j=d.find(p4,s)
        if j<0: break
        if TS<=j<TE: sites.append(j)
        s=j+1
    print('  %-22s VA=0x%08X file=0x%06X  .text xrefs=%s' % (lab, va, va2off(va) or 0, [hex(x) for x in sites]))
    for si in sites[:3]:
        a=max(TS,si-24); b=min(TE,si+18)
        print('       ctx 0x%06X: %s' % (si, ' '.join('%02X'%x for x in d[a:b])))

print()
print('### duplicate "Data/Config.gjd" and other .gjd strings: first 6 with context ###')
for o,t in names[:6]:
    a=max(0,o-8)
    print('  0x%06X %-24s prev bytes: %s' % (o, t, ' '.join('%02X'%x for x in d[a:o])))

print()
print('### section table (final) ###')
print('  %-9s %10s %10s %10s %10s %8s' % ('name','vaddr','vsize','rawptr','rawsize','flags'))
for s in p.sections:
    print('  %-9s 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X' % (
        s['name'], s['vaddr'], s['vsize'], s['rawptr'], s['rawsize'], s['chars']))
