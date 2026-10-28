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
def va2off(v): return p.rva2off(v-p.image_base)

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

SIB={0x85:'eax',0x8D:'ecx',0x95:'edx',0x9D:'ebx',0xA5:'esp',0xAD:'ebp',0xB5:'esi',0xBD:'edi'}
print('=== jump tables: entry count + preceding "range check" immediate ===')
rows=[]
for i in range(TS,TE-7):
    if d[i]==0xFF and d[i+1]==0x24 and d[i+2] in SIB:
        tbl=struct.unpack_from('<I',d,i+3)[0]; to=va2off(tbl)
        if to is None: continue
        vals=[]
        for k in range(600):
            if to+4*k+4>len(d): break
            v=struct.unpack_from('<I',d,to+4*k)[0]
            if v==0: break
            vals.append(v)
        if len(vals)<5: continue
        offs=[va2off(v) for v in vals]
        if any(o is None or not(TS<=o<TE) for o in offs): continue
        # look back up to 40 bytes for a cmp/sub with a mid-size immediate
        back=d[max(TS,i-48):i]
        rc=None
        for m in range(len(back)-5):
            if back[m]==0x3D:
                v=struct.unpack_from('<I',back,m+1)[0]
                if 20<=v<=600: rc=('cmp eax,%d'%v)
            if back[m]==0x83 and ((back[m+1]>>3)&7)==7:
                v=struct.unpack_from('<b',back,m+2)[0]&0xFFFFFFFF
                if 20<=v<=600: rc=('cmp r/m32,%d'%v)
            if back[m]==0x2D and False: pass
        rows.append((len(vals), i, SIB[d[i+2]], to, rc))

rows.sort(key=lambda r:-r[0])
for n,site,reg,to,rc in rows[:45]:
    print('  cases=%-4d site=0x%06X rva=0x%06X idx=%-3s tblfile=0x%06X  rangecheck=%s' % (
        n, site, rva(site), reg, to, rc))

print()
print('=== tables with 30-45 entries (item-type-dispatch candidates) ===')
for n,site,reg,to,rc in rows:
    if 28<=n<=48:
        print('  cases=%-4d site=0x%06X rva=0x%06X idx=%-3s tblfile=0x%06X rangecheck=%s' % (n,site,rva(site),reg,to,rc))

print()
print('=== disassemble around 根骨[ / 机缘[ refs (file 0x0AEC00-0x0AF100) ===')
def annotate(o,raw):
    note=''; k=0
    while k<len(raw) and raw[k] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): k+=1
    if k>=len(raw): return note
    op=raw[k]
    try:
        if op==0x83 and k+3<=len(raw) and ((raw[k+1]>>3)&7)==7: note='  ; cmp ...,%d'%(struct.unpack_from('<b',raw,k+2)[0]&0xFFFFFFFF)
        elif op==0x68 and k+5<=len(raw):
            v=struct.unpack_from('<I',raw,k+1)[0]
            if v in strs: note='  ; "%s"'%strs[v][:60]
        elif op==0x6A and k+2<=len(raw): note='  ; push %d'%(struct.unpack_from('<b',raw,k+1)[0]&0xFFFFFFFF)
        elif op==0xE8 and k+5<=len(raw): note='  ; call 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
        elif op==0x0F and k+6<=len(raw) and 0x80<=raw[k+1]<=0x8F: note='  ; jcc 0x%06X'%(o+k+6+struct.unpack_from('<i',raw,k+2)[0])
        elif op==0xEB and k+2<=len(raw): note='  ; jmp 0x%06X'%(o+k+2+struct.unpack_from('<b',raw,k+1)[0])
        elif op==0xE9 and k+5<=len(raw): note='  ; jmp 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
    except Exception: pass
    return note
o=0x0AEC00
while o<0x0AF100:
    L=insn_len(d,o)
    if L==0: print('  0x%06X  ??? %s'%(o,' '.join('%02X'%x for x in d[o:o+8]))); o+=1; continue
    raw=d[o:o+L]
    print('  0x%06X  %-32s%s'%(o,' '.join('%02X'%x for x in raw[:14]),annotate(o,raw)))
    o+=L
