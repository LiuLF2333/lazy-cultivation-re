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

def annotate(o,raw):
    note=''; k=0
    while k<len(raw) and raw[k] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): k+=1
    if k>=len(raw): return note
    op=raw[k]
    try:
        if op==0x83 and k+3<=len(raw) and ((raw[k+1]>>3)&7)==7:
            note='  ; cmp ...,%d'%(struct.unpack_from('<b',raw,k+2)[0]&0xFFFFFFFF)
        elif op==0x81 and ((raw[k+1]>>3)&7)==7:
            e=modrm_extent(raw,k+1)
            if k+1+e+4<=len(raw): note='  ; cmp ...,%d'%struct.unpack_from('<I',raw,k+1+e)[0]
        elif op==0x3D and k+5<=len(raw): note='  ; cmp eax,%d'%struct.unpack_from('<I',raw,k+1)[0]
        elif op==0x68 and k+5<=len(raw):
            v=struct.unpack_from('<I',raw,k+1)[0]
            note='  ; push %d'%v
            if v in strs: note+=' ("%s")'%strs[v][:40]
        elif op==0x6A and k+2<=len(raw): note='  ; push %d'%(struct.unpack_from('<b',raw,k+1)[0]&0xFFFFFFFF)
        elif op==0xE8 and k+5<=len(raw): note='  ; call 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
        elif op==0x0F and k+6<=len(raw) and 0x80<=raw[k+1]<=0x8F: note='  ; jcc 0x%06X'%(o+k+6+struct.unpack_from('<i',raw,k+2)[0])
        elif op==0xEB and k+2<=len(raw): note='  ; jmp 0x%06X'%(o+k+2+struct.unpack_from('<b',raw,k+1)[0])
        elif op==0xE9 and k+5<=len(raw): note='  ; jmp 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
    except Exception: pass
    return note

def sites_for(t):
    pat=b'\x68'+struct.pack('<I',t); out=[]; s=0
    while True:
        j=d.find(pat,s)
        if j<0: break
        if TS<=j<TE: out.append(j)
        s=j+1
    return out

def func_bounds(inner):
    """find enclosing function by scanning back for 55 8B EC (push ebp; mov ebp,esp) preceded by CC"""
    best=None
    for s in range(max(TS,inner-0x8000), inner):
        if d[s]==0x55 and d[s+1]==0x8B and d[s+2]==0xEC and (s<TS+2 or d[s-1]==0xCC or d[s-2]==0xCC):
            o=s; ok=True
            while o<inner:
                L=insn_len(d,o)
                if L==0 or o+L>inner: ok=False; break
                o+=L
            if ok: best=s
    return best

for t in (132,129,130,131):
    ss=sites_for(t)
    print('='*84)
    print('### push imm32 %d  ->  %d sites in .text' % (t, len(ss)))
    for site in ss:
        fs=func_bounds(site)
        # count other item-type immediates in a window around
        print('-'*70)
        print('  site 0x%06X (rva 0x%06X)  enclosing func start = %s' % (
            site, rva(site), ('0x%06X'%fs) if fs else 'NOT FOUND'))
        start = max(TS, (fs if fs else site-0x60) - 0x20)
        end   = min(TE, site+0x60)
        o=start
        while o<end:
            L=insn_len(d,o)
            if L==0: print('    0x%06X  ??? %s'%(o,' '.join('%02X'%x for x in d[o:o+8]))); o+=1; continue
            raw=d[o:o+L]
            mark='   <<<<' if o==site else ''
            print('    0x%06X  %-30s%s%s'%(o,' '.join('%02X'%x for x in raw[:12]),annotate(o,raw),mark))
            o+=L
