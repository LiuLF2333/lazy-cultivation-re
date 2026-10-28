import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
RD   = next(s for s in p.sections if s['name']=='.rdata')
DATA = next(s for s in p.sections if s['name']=='.data')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def va2off(v): return p.rva2off(v-p.image_base)

# build a map of utf16 & ascii string starts (VA -> text)
strs = {}
for s in p.sections:
    a,b = s['rawptr'], s['rawptr']+s['rawsize']
    i = a
    while i < b:
        # try utf-16
        j=i; chars=[]; 
        while j+1 < b:
            cp = d[j]|(d[j+1]<<8)
            if cp==0: break
            if (0x20<=cp<0x7f) or (0x4e00<=cp<=0x9fff) or (0x3000<=cp<=0x303f) or (0xff00<=cp<=0xffef) or cp in (0x2026,0x2014,0x2018,0x2019,0x201c,0x201d,0xb7):
                chars.append(cp); j+=2
            else: chars=None; break
        if chars and len(chars)>=3 and j+1<b and d[j]==0 and d[j+1]==0:
            r=p.off2rva(i)
            if r is not None: strs[r+p.image_base] = ''.join(chr(c) for c in chars)
            i=j+2; continue
        # ascii
        j=i; ch=[]
        while j<b and 0x20<=d[j]<0x7f:
            ch.append(chr(d[j])); j+=1
        if len(ch)>=4 and j<b and d[j]==0:
            r=p.off2rva(i)
            if r is not None: strs[r+p.image_base] = ''.join(ch)
            i=j+1; continue
        i+=1
print('string starts indexed:', len(strs))

def region_report(a, b, title):
    print('='*80); print('### %s : file 0x%X-0x%X  (rva 0x%X-0x%X)' % (title,a,b,a-TS+TEXT['vaddr'],b-TS+TEXT['vaddr']))
    refs = collections.OrderedDict()
    for i in range(a, b-5):
        b0 = d[i]
        val=None
        if b0 == 0x68:                      # push imm32
            val = struct.unpack_from('<I', d, i+1)[0]
        elif 0xB8 <= b0 <= 0xBF:            # mov r32, imm32
            val = struct.unpack_from('<I', d, i+1)[0]
        if val is None: continue
        if val in strs:
            refs.setdefault(val, []).append(i)
    print('  distinct string literals referenced: %d' % len(refs))
    for va, sites in refs.items():
        print('   0x%08X (rva 0x%06X) x%-3d  %s' % (va, va-p.image_base, len(sites), strs[va][:96]))

region_report(0x209C00, 0x20B200, 'ITEM-USE CANDIDATE A')
region_report(0x214E00, 0x217200, 'ITEM-USE CANDIDATE B')
region_report(0x212300, 0x212600, 'small cmp-110 site C')
