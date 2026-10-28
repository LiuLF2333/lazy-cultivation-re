import io, sys, os, struct, collections, importlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
import x86len; importlib.reload(x86len)
from x86len import insn_len, modrm_extent
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def fo2va(o):
    r=p.off2rva(o); return None if r is None else r+p.image_base
def rd_utf16(off,n=80):
    out=[]
    for k in range(n):
        cp=d[off+2*k]|(d[off+2*k+1]<<8)
        if cp==0: break
        if 0xD800 <= cp <= 0xDFFF: return ''   # surrogate -> not a real UTF-16 string
        if cp < 0x20 and cp not in (9,10,13): return ''
        out.append(chr(cp))
    return ''.join(out)

# ---------- build IAT slot VA -> dll!func ----------
imp_rva,_ = p.dd[1]; off=p.rva2off(imp_rva)
iat={}
i=0
while True:
    ent=d[off+i*20: off+i*20+20]
    oft,ts,fc,namerva,firstthunk = struct.unpack('<IIIII',ent)
    if namerva==0 and firstthunk==0: break
    noff=p.rva2off(namerva); dll=d[noff:d.index(b'\0',noff)].decode('latin1')
    toff=p.rva2off(oft) if oft else p.rva2off(firstthunk)
    j=0
    while True:
        v=struct.unpack_from('<I',d,toff+j*4)[0]
        if v==0: break
        if v & 0x80000000:
            fn='ORD_%d'%(v&0xFFFF)
        else:
            fo=p.rva2off(v); fn=d[fo+2:d.index(b'\0',fo+2)].decode('latin1')
        iat[firstthunk+j*4] = '%s!%s' % (dll, fn)
        j+=1
    i+=1
print('IAT slots mapped:', len(iat))

def annotate(o,raw):
    note=''; k=0
    while k<len(raw) and raw[k] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): k+=1
    if k>=len(raw): return note
    op=raw[k]
    try:
        # FF 15 <abs32>  call dword ptr [abs]
        if op==0xFF and raw[k+1]==0x15 and k+6<=len(raw):
            tgt=struct.unpack_from('<I',raw,k+2)[0]
            rva_t=tgt-p.image_base
            note='  ; call [0x%08X]'%tgt
            nm=iat.get(rva_t)
            note += ' = %s'%nm if nm else ' (rva 0x%X unknown)'%rva_t
        elif op==0x68 and k+5<=len(raw):
            v=struct.unpack_from('<I',raw,k+1)[0]
            oo=p.rva2off(v-p.image_base)
            note='  ; push 0x%08X'%v
            if oo is not None:
                s=rd_utf16(oo,60)
                if s and all(0x20<=ord(c)<0x10000 for c in s): note+=' "%s"'%s[:52]
        elif op==0xE8 and k+5<=len(raw): note='  ; call 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
        elif op==0x6A and k+2<=len(raw): note='  ; push %d'%(struct.unpack_from('<b',raw,k+1)[0]&0xFFFFFFFF)
        elif op==0x0F and k+6<=len(raw) and 0x80<=raw[k+1]<=0x8F: note='  ; jcc 0x%06X'%(o+k+6+struct.unpack_from('<i',raw,k+2)[0])
        elif op==0xEB and k+2<=len(raw): note='  ; jmp 0x%06X'%(o+k+2+struct.unpack_from('<b',raw,k+1)[0])
        elif op==0xE9 and k+5<=len(raw): note='  ; jmp 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
    except Exception: pass
    return note

# ---------- disassemble MOD loader region ----------
print()
print('### MOD loader region: file 0x0C6C00-0x0C9800  -- imported APIs + strings used ###')
used=collections.Counter(); lines=[]
o=0x0C6C00; end=0x0C9800
while o<end:
    L=insn_len(d,o)
    if L==0: o+=1; continue
    raw=d[o:o+L]; note=annotate(o,raw)
    if note.strip(): lines.append('  0x%06X  %-28s%s'%(o,' '.join('%02X'%x for x in raw[:10]),note))
    if '= ' in note:
        used[note.split('= ')[1].strip()]+=1
    o+=L
open(r"D:\XiuXian\_analysis\re\out\mod_loader.txt",'w',encoding='utf-8').write('\n'.join(lines))
print('  annotated lines written:', len(lines))
print()
print('  imported APIs used in MOD region:')
for nm,c in used.most_common(30):
    print('     %-40s x%d' % (nm,c))

# ---------- function boundaries in MOD region ----------
print()
print('### function starts (after CC pad) in file 0x0C6C00-0x0C9800 ###')
o=0x0C6C00
sts=[]
while o<0x0C9800-1:
    if d[o]==0xCC:
        j=o
        while d[j]==0xCC: j+=1
        if j-o>=2: sts.append(j)
        o=j
    else: o+=1
for s in sts[:40]:
    print('   0x%06X  rva 0x%06X' % (s, s-TS+TEXT['vaddr']))
print('   count:', len(sts))
