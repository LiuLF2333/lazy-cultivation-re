import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
from x86len import insn_len
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def va2off(v): return p.rva2off(v-p.image_base)
def off2va(o):
    r=p.off2rva(o); return None if r is None else r+p.image_base

# ---------- index string starts ----------
strs = {}
for s in p.sections:
    a,b = s['rawptr'], s['rawptr']+s['rawsize']; i=a
    while i < b:
        j=i; ch=[]
        while j+1<b:
            cp=d[j]|(d[j+1]<<8)
            if cp==0: break
            if (0x20<=cp<0x7f) or (0x4e00<=cp<=0x9fff) or (0x3000<=cp<=0x303f) or (0xff00<=cp<=0xffef) or cp in (0x2026,0x2014,0x2018,0x2019,0x201c,0x201d):
                ch.append(cp); j+=2
            else: ch=None; break
        if ch and len(ch)>=3 and j+1<b and d[j]==0 and d[j+1]==0:
            r=p.off2rva(i)
            if r is not None: strs[r+p.image_base]=''.join(chr(c) for c in ch)
            i=j+2; continue
        j=i; ch=[]
        while j<b and 0x20<=d[j]<0x7f: ch.append(chr(d[j])); j+=1
        if len(ch)>=4 and j<b and d[j]==0:
            r=p.off2rva(i)
            if r is not None: strs[r+p.image_base]=''.join(ch)
            i=j+1; continue
        i+=1

# ---------- find function starts: byte after >=2 0xCC pad, or after ret ----------
starts = set([TS])
i = TS
while i < TE-2:
    if d[i]==0xCC and d[i+1]==0xCC:
        j=i
        while j<TE and d[j]==0xCC: j+=1
        if j<TE: starts.add(j)
        i=j
    else:
        i+=1
starts = sorted(starts)
print('candidate function starts:', len(starts))

ITEMTYPES = set([100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,
                 120,121,122,123,124,125,126,127,128,129,130,131,132,133,
                 200,201,202,203,204,300,301,302,303,304])
FOCUS = [105,106,110,132,123,115,200,300,106]

funcs = []
for si in range(len(starts)-1):
    a, b = starts[si], starts[si+1]
    if b-a > 0x20000: continue
    insns = []
    o = a; ok = True
    while o < b:
        L = insn_len(d, o)
        if L == 0 or o+L > b:
            ok = False; break
        insns.append((o, L, d[o:o+L]))
        o += L
    if ok and insns:
        funcs.append((a, b, insns))
print('decoded functions:', len(funcs))

# ---------- classify: which functions compare against item-type codes ----------
def scan_func(insns):
    cmps = []            # (offset, imm)
    pushes = {}          # offset -> string
    for (o, L, raw) in insns:
        # cmp r/m32, imm8 : 83 /7 ib
        k = 0
        while k < L and raw[k] in (0x2E,0x36,0x3E,0x26,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3): k+=1
        if k < L:
            op = raw[k]
            if op == 0x83 and k+2 < L:
                modrm = raw[k+1]
                if ((modrm>>3)&7)==7:
                    cmps.append((o, raw[k+2], 'cmp r/m32,imm8'))
            elif op == 0x3D and k+4 < L:
                cmps.append((o, struct.unpack_from('<I', raw, k+1)[0], 'cmp eax,imm32'))
            elif op == 0x81 and k+5 < L:
                modrm = raw[k+1]
                if ((modrm>>3)&7)==7:
                    cmps.append((o, struct.unpack_from('<I', raw, k+2)[0], 'cmp r/m32,imm32'))
            elif op == 0x68 and k+5 <= L:
                v = struct.unpack_from('<I', raw, k+1)[0]
                if v in strs: pushes[o] = strs[v]
            elif 0xB8 <= op <= 0xBF and k+5 <= L:
                v = struct.unpack_from('<I', raw, k+1)[0]
                if v in strs: pushes[o] = strs[v]
    return cmps, pushes

report = []
for a, b, insns in funcs:
    cmps, pushes = scan_func(insns)
    imms = set(i for _, i, _ in cmps)
    hit = imms & ITEMTYPES
    if len(hit) >= 3:
        report.append((len(hit), a, b, cmps, pushes, imms))

report.sort(key=lambda x: -x[0])
print()
print('=== functions comparing against >=3 item-type codes ===')
for n, a, b, cmps, pushes, imms in report[:25]:
    print('-'*78)
    print('FUNC file=0x%06X rva=0x%06X size=%-6d  distinct item-type consts=%d' % (a, a-TS+TEXT['vaddr'], b-a, n))
    print('   consts: %s' % sorted(imms & ITEMTYPES))
    print('   cmp sites:')
    for o, imm, kind in cmps:
        mark = ' <<<' if imm in ITEMTYPES else ''
        print('      0x%06X  %-18s imm=0x%X (%d)%s' % (o, kind, imm, imm, mark))
    if pushes:
        print('   string literals:')
        for o, s in list(pushes.items())[:12]:
            print('      0x%06X  %s' % (o, s[:88]))
print()
print('total candidate functions:', len(report))
