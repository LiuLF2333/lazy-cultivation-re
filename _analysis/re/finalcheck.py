import io, sys, os, struct, importlib, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']

ITEMS=[0,100,105,106,107,108,110,112,113,114,115,116,117,118,119,120,121,122,123,124,126,127,
       128,129,130,131,132,200,201,202,203,204,300,302,303,999]

print('=== RAW byte search (upper bound, over-inclusive) for each type1 as an immediate in .text ===')
print('    forms: 3D <imm32>            cmp eax,imm32')
print('           81 F8..FF <imm32>     cmp r32,imm32')
print('           83 F8..FF <imm8>      cmp r32,imm8 (only if value<=127)')
print('           68 <imm32>            push imm32')
print('           6A <imm8>             push imm8 (only if value<=127)')
print()
hdr = '%-6s %-8s %-10s %-10s %-8s %-8s %s' % ('type1','cmp3D','cmp81r32','cmp83r8','push68','push6A','ALL')
print(hdr); print('-'*len(hdr))
results={}
for t in ITEMS:
    hexs=[hex(t)]
    forms={}
    if t < 0x100:
        forms['cmp3D']   = bytes([0x3D, t,0,0,0])
        forms['cmp83r8'] = sum(1 for reg in range(8) if d.find(bytes([0x83,0xF8|reg,t]))>=0)
        forms['push6A']  = 1 if d.find(bytes([0x6A,t]))>=0 else 0
    else:
        forms['cmp3D']=bytes([0x3D])+struct.pack('<I',t)
        forms['cmp83r8']=0; forms['push6A']=0
    forms['cmp81r32']=sum(1 for reg in range(8) if d.find(bytes([0x81,0xF8|reg])+struct.pack('<I',t))>=0)
    forms['push68']=1 if d.find(b'\x68'+struct.pack('<I',t))>=0 else 0
    # count raw occurrences restricted to .text for the 32-bit forms
    def cnt(pat):
        c=0; s=0
        while True:
            j=d.find(pat,s)
            if j<0: break
            if TS<=j<TE: c+=1
            s=j+1
        return c
    n3d = cnt(forms['cmp3D']) if isinstance(forms['cmp3D'],bytes) else 0
    n81 = cnt(bytes([0x81,0xF8])+struct.pack('<I',t)) + cnt(bytes([0x81,0xF9])+struct.pack('<I',t)) + \
          cnt(bytes([0x81,0xFA])+struct.pack('<I',t)) + cnt(bytes([0x81,0xFB])+struct.pack('<I',t)) + \
          cnt(bytes([0x81,0xFC])+struct.pack('<I',t)) + cnt(bytes([0x81,0xFD])+struct.pack('<I',t)) + \
          cnt(bytes([0x81,0xFE])+struct.pack('<I',t)) + cnt(bytes([0x81,0xFF])+struct.pack('<I',t))
    n83 = 0
    if t < 0x80:
        for reg in range(8): n83 += cnt(bytes([0x83,0xF8|reg,t]))
    n68 = cnt(b'\x68'+struct.pack('<I',t))
    n6a = cnt(bytes([0x6A,t])) if t<0x100 else 0
    tot = n3d+n81+n83+n68+n6a
    results[t]=tot
    mark = '  <== ZERO' if tot==0 else ''
    print('%-6d %-8d %-10d %-10d %-8d %-8d %-5d%s' % (t, n3d, n81, n83, n68, n6a, tot, mark))

print()
print('=== summary: values with ZERO immediate occurrences in .text ===')
print('   ', [t for t in ITEMS if results[t]==0])
