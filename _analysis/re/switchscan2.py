import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS, TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']

def off2va(o):
    r = p.off2rva(o); return None if r is None else r + p.image_base
def va2off(v): return p.rva2off(v - p.image_base)

# SIB byte for jmp [reg*4 + disp32]: scale=2(bits10), index=reg, base=5(disp32)
SIB = {0x85:'eax',0x8D:'ecx',0x95:'edx',0x9D:'ebx',0xA5:'esp',0xAD:'ebp',0xB5:'esi',0xBD:'edi'}

print('=== searching for "jmp dword ptr [reg*4+disp32]"  (FF 24 <sib> <imm32>) ===')
tables = []
for i in range(TS, TE-7):
    if d[i]==0xFF and d[i+1]==0x24 and d[i+2] in SIB:
        tbl = struct.unpack_from('<I', d, i+3)[0]
        tables.append((i, SIB[d[i+2]], tbl))
print('found: %d' % len(tables))

valid = []
for site, reg, tbl in tables:
    to = va2off(tbl)
    if to is None or to+8 > len(d): continue
    vals=[]
    for k in range(400):
        if to+4*k+4 > len(d): break
        v = struct.unpack_from('<I', d, to+4*k)[0]
        if v==0: break
        vals.append(v)
    if len(vals)<3: continue
    offs=[va2off(v) for v in vals]
    if any(o is None or not (TS<=o<TE) for o in offs): continue
    valid.append((site,reg,tbl,to,vals,offs))

print('validated switch tables in .text: %d' % len(valid))
print()
for site,reg,tbl,to,vals,offs in sorted(valid, key=lambda x:-len(x[4]))[:40]:
    print('site=0x%06X rva=0x%06X idx=%-3s cases=%-4d table@file=0x%06X rva=0x%06X targets 0x%X..0x%X' % (
        site, site-TS+TEXT['vaddr'], reg, len(vals), to, tbl-p.image_base,
        min(vals)-p.image_base, max(vals)-p.image_base))

print()
print('=== searching for "mov reg, [reg*4+disp32]" jump-table loads then jmp reg (MSVC style) ===')
# MSVC also emits: mov eax,[ecx*4+<tbl>] ; jmp eax   -> 8B 04 8D <disp32> FF E0
cnt=0
for i in range(TS, TE-9):
    if d[i]==0x8B and d[i+1]==0x04 and d[i+2] in (0x85,0x8D,0x95,0x9D,0xB5,0xAD,0xBD) and d[i+7]==0xFF and d[i+8]==0xE0:
        tbl = struct.unpack_from('<I', d, i+3)[0]
        to = va2off(tbl)
        if to is None: continue
        vals=[]
        for k in range(400):
            if to+4*k+4>len(d): break
            v=struct.unpack_from('<I', d,to+4*k)[0]
            if v==0: break
            vals.append(v)
        if len(vals)<3: continue
        offs=[va2off(v) for v in vals]
        if any(o is None or not (TS<=o<TE) for o in offs): continue
        cnt+=1
        if cnt<=25:
            print('  mov/jmp table site=0x%06X cases=%-4d table rva=0x%06X' % (i, len(vals), tbl-p.image_base))
print('  total mov/jmp tables:', cnt)
