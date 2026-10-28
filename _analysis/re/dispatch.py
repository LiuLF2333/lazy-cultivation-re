import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS, TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
RD = next(s for s in p.sections if s['name']=='.rdata')
def va2off(v): return p.rva2off(v-p.image_base)
def intext(o): return o is not None and TS <= o < TE

SIB = {0x85:'eax',0x8D:'ecx',0x95:'edx',0x9D:'ebx',0xA5:'esp',0xAD:'ebp',0xB5:'esi',0xBD:'edi'}

print('=== ALL "FF 14 <sib> disp32" (call [reg*4+disp]) and "FF 24 <sib> disp32" (jmp) ===')
for opc, label in ((0x14,'CALL'), (0x24,'JMP ')):
    n=0; good=0
    for i in range(TS, TE-7):
        if d[i]==0xFF and d[i+1]==opc and d[i+2] in SIB:
            n+=1
            tbl = struct.unpack_from('<I', d, i+3)[0]
            to = va2off(tbl)
            ok='?'
            cnt=0
            if to is not None and 0 <= to < len(d)-4:
                for k in range(400):
                    if to+4*k+4>len(d): break
                    v=struct.unpack_from('<I',d,to+4*k)[0]
                    if v==0: break
                    cnt+=1
                if cnt>=3:
                    o1=va2off(struct.unpack_from('<I',d,to)[0])
                    ok='TEXT' if intext(o1) else ('RDATA' if o1 is not None else 'bad')
                    if ok in ('TEXT','RDATA'): good+=1
            print('  %s site=0x%06X rva=0x%06X idx=%-3s tblRVA=0x%08X tblfile=%s entries=%d targets=%s' % (
                label, i, i-TS+TEXT['vaddr'], SIB[d[i+2]], tbl-p.image_base,
                ('0x%X'%to) if to is not None else 'NONE', cnt, ok))
    print('  -> %s total=%d usable=%d' % (label, n, good))
    print()

print('=== byte-pattern scan for comparisons against item type1 codes ===')
CODES = {'106':0x6A, '110':0x6E, '132':0x84, '200':0xC8, '300':0x2C, '123':0x7B, '105':0x69}
# forms producing "cmp r/m32, imm8" = 83 /7 ib   and "cmp r32,imm8"=83 F8..FF ib
for name, imm in CODES.items():
    pats = []
    for reg in range(8):
        pats.append(bytes([0x83, 0xC0|(7<<3)|reg, imm]))   # cmp r32, imm8
    pats.append(bytes([0x3D, imm,0,0,0]))                  # cmp eax, imm32
    hits = []
    for pt in pats:
        s=0
        while True:
            j=d.find(pt, s)
            if j<0: break
            if TS<=j<TE: hits.append(j)
            s=j+1
    print('  cmp ...,0x%02X (%s): %d sites in .text  %s' % (imm, name, len(hits), [hex(h) for h in hits[:12]]))
