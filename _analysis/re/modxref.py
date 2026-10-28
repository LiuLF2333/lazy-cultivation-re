import io, sys, os, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def fo2rva(o): return p.off2rva(o)
def fo2va(o):
    r=p.off2rva(o); return None if r is None else r+p.image_base
def rd_utf16(off,n=80):
    out=[]
    for k in range(n):
        cp=d[off+2*k]|(d[off+2*k+1]<<8)
        if cp==0: break
        out.append(chr(cp))
    return ''.join(out)

print('### MOD / config / save strings by FILE OFFSET -> RVA -> VA ###')
FOFFS=[(0x28EAD4,'.EXE'),(0x28EAE0,'SelMod'),(0x28EB1C,'ModConfig'),(0x28EABC,'config.ini'),
       (0x290F80,'SelMod'),(0x290FC4,'SelMod'),(0x290FD4,'Mods\\'),(0x291230,'原版'),
       (0x291238,'\\*.*'),(0x291244,'Mods\\'),(0x291258,'.'),(0x29125C,'Mods\\'),
       (0x291274,'explorer'),(0x291288,'http://www.guajigame.com/modManage.html'),
       (0x2912D8,'重新扫描完成'),(0x291300,'刷新MOD信息完成'),(0x291318,'config.ini'),
       (0x291330,'ModConfig'),(0x291344,'SelMod'),(0x291354,'\\Res\\'),(0x291360,'Mods\\'),
       (0x291378,'\\Data\\'),(0x291388,'ModConfig'),(0x29139C,'config.ini'),(0x2913B4,'config.ini'),
       (0x28EC18,'Mod使用说明...'),(0x291018,'读取资源失败...'),(0x28EBE4,'选择使用的版本...')]
rows=[]
for fo,lab in FOFFS:
    va=fo2va(fo)
    rows.append((fo,va,rd_utf16(fo,90)))

print('  %-10s %-12s %-38s' % ('file','VA','string'))
for fo,va,s in rows:
    print('  0x%06X  0x%08X  %r' % (fo, va, s[:70]))

print()
print('### .text xrefs for each MOD string (correct VA) ###')
for fo,va,s in rows:
    sites=[]; k=0; pat=struct.pack('<I',va)
    while True:
        j=d.find(pat,k)
        if j<0: break
        if TS<=j<TE: sites.append(j)
        k=j+1
    tag=''
    if sites:
        si=sites[0]
        # is it push imm32?
        tag = 'push' if d[si-1]==0x68 else ('mov' if 0xB8<=d[si-1]<=0xBF else 'raw')
    print('  %-34s VA=0x%08X  xrefs=%-2d %s %s' % (repr(s[:30]), va, len(sites),
          [hex(x) for x in sites[:5]], tag))

print()
print('### disassemble the \\Data\\ xref context (Mods\\<name>\\Data) ###')
from x86len import insn_len, modrm_extent
import importlib, x86len; importlib.reload(x86len)
from x86len import insn_len, modrm_extent

def annotate(o,raw):
    note=''; k=0
    while k<len(raw) and raw[k] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): k+=1
    if k>=len(raw): return note
    op=raw[k]
    try:
        if op==0x68 and k+5<=len(raw):
            v=struct.unpack_from('<I',raw,k+1)[0]
            note='  ; push 0x%08X'%v
            oo=p.rva2off(v-p.image_base)
            if oo: note+=' "%s"'%rd_utf16(oo,48)
        elif op==0xE8 and k+5<=len(raw): note='  ; call 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
        elif op==0x6A and k+2<=len(raw): note='  ; push %d'%(struct.unpack_from('<b',raw,k+1)[0]&0xFFFFFFFF)
        elif op==0x0F and k+6<=len(raw) and 0x80<=raw[k+1]<=0x8F: note='  ; jcc 0x%06X'%(o+k+6+struct.unpack_from('<i',raw,k+2)[0])
        elif op==0xEB and k+2<=len(raw): note='  ; jmp 0x%06X'%(o+k+2+struct.unpack_from('<b',raw,k+1)[0])
        elif op==0xE9 and k+5<=len(raw): note='  ; jmp 0x%06X'%(o+k+5+struct.unpack_from('<i',raw,k+1)[0])
    except Exception: pass
    return note

# xref site for \Data\
dx = fo2va(0x291378)
hits=[]
k=0; pat=struct.pack('<I',dx)
while True:
    j=d.find(pat,k)
    if j<0: break
    if TS<=j<TE: hits.append(j)
    k=j+1
print('  \\Data\\ VA=0x%08X sites=%s' % (dx,[hex(x) for x in hits]))
for si in hits[:2]:
    a=max(TS,si-0x70); b=min(TE,si+0x50)
    o=a
    while o<b:
        L=insn_len(d,o)
        if L==0: print('    0x%06X ???'%o); o+=1; continue
        raw=d[o:o+L]
        print('    0x%06X  %-28s%s%s'%(o,' '.join('%02X'%x for x in raw[:12]),annotate(o,raw),'  <<<<' if o==si-1 else ''))
        o+=L
