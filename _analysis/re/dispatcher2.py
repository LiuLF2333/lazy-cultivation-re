import io, sys, os, struct, importlib
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

def annotate(o, raw):
    note=''
    k=0
    while k<len(raw) and raw[k] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): k+=1
    if k>=len(raw): return note
    op=raw[k]
    try:
        if op==0x83 and k+3<=len(raw) and ((raw[k+1]>>3)&7)==7:
            note='   ; cmp ...,%d'%(struct.unpack_from('<b',raw,k+2)[0] & 0xFFFFFFFF)
        elif op==0x81 and ((raw[k+1]>>3)&7)==7:
            e=modrm_extent(raw,k+1)
            if k+1+e+4<=len(raw): note='   ; cmp ...,%d'%struct.unpack_from('<I',raw,k+1+e)[0]
        elif op==0x3D and k+5<=len(raw): note='   ; cmp eax,%d'%struct.unpack_from('<I',raw,k+1)[0]
        elif op==0x68 and k+5<=len(raw):
            v=struct.unpack_from('<I',raw,k+1)[0]
            if v in strs: note='   ; "%s"'%strs[v][:60]
        elif op==0x6A and k+2<=len(raw): note='   ; push %d'%(struct.unpack_from('<b',raw,k+1)[0] & 0xFFFFFFFF)
        elif op==0xE8 and k+5<=len(raw): note='   ; call 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
        elif op==0x0F and k+6<=len(raw) and 0x80<=raw[k+1]<=0x8F:
            note='   ; jcc 0x%06X'%(o+k+6+struct.unpack_from('<i',raw,k+2)[0])
        elif op==0xEB and k+2<=len(raw): note='   ; jmp 0x%06X'%(o+k+2+struct.unpack_from('<b',raw,k+1)[0])
        elif op==0xE9 and k+5<=len(raw): note='   ; jmp 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
    except Exception: pass
    return note

def dis(start, end, title, fh):
    fh.write('\n'+'='*84+'\n### %s  file 0x%X-0x%X (rva 0x%X-0x%X)\n'%(title,start,end,rva(start),rva(end)))
    o=start; prev_ret=False
    while o<end:
        L=insn_len(d,o)
        if L==0:
            fh.write('  0x%06X  ??? %s\n'%(o,' '.join('%02X'%x for x in d[o:o+8]))); o+=1; continue
        raw=d[o:o+L]
        fh.write('  0x%06X  %-34s%s\n'%(o,' '.join('%02X'%x for x in raw[:14]), annotate(o,raw)))
        o+=L

with open(r"D:\XiuXian\_analysis\re\out\dispatcher.txt",'w',encoding='utf-8') as fh:
    dis(0x20A0A2, 0x20AA00, 'ITEM-USE DISPATCHER', fh)
print('written')
# print cmp lines only
lines=open(r"D:\XiuXian\_analysis\re\out\dispatcher.txt",encoding='utf-8').read().splitlines()
print('total lines',len(lines))
for l in lines:
    if 'cmp ...' in l: print(l)
