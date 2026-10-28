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

print('=== all "cmp dword [reg+0x290], imm8"  (83 B8..BF 90 02 00 00 xx) in .text ===')
found=[]
for i in range(TS,TE-8):
    if d[i]==0x83 and 0xB8<=d[i+1]<=0xBF and d[i+2:i+6]==b'\x90\x02\x00\x00':
        imm=d[i+6]
        found.append((i,imm))
print('count:', len(found))
c=collections.Counter(imm for _,imm in found)
print('distinct immediates:', len(c))
for imm,n in sorted(c.items()):
    sites=[hex(o) for o,im in found if im==imm]
    print('   imm=%-5d x%-3d  %s' % (imm,n,sites[:8]))

print()
print('=== also cmp [reg+0x290], imm32  (81 B8..BF 90 02 00 00 xxxxxxxx) ===')
f2=[]
for i in range(TS,TE-11):
    if d[i]==0x81 and 0xB8<=d[i+1]<=0xBF and d[i+2:i+6]==b'\x90\x02\x00\x00':
        f2.append((i,struct.unpack_from('<I',d,i+6)[0]))
print('count:', len(f2), sorted(set(im for _,im in f2)))

print()
print('=== for reference: item types present in ItemTable ===')
ITEMS=[0,100,105,106,107,108,110,112,113,114,115,116,117,118,119,120,121,122,123,124,126,127,128,129,130,131,132,200,201,202,203,204,300,302,303]
print('  ', ITEMS)
imm_set = set(im for _,im in found) | set(im for _,im in f2)
print('  overlaps with item types:', sorted(imm_set & set(ITEMS)))
print('  non-item immediates     :', sorted(imm_set - set(ITEMS)))

print()
print('=== other offsets used as switch fields in the item-use function 0x075B40-0x078C8C ===')
offs=collections.Counter()
for i in range(0x075B40, 0x078C8C-8):
    if d[i]==0x83 and 0xB8<=d[i+1]<=0xBF:
        disp=struct.unpack_from('<I',d,i+2)[0]
        if disp < 0x1000:
            offs[disp]+=1
    if d[i]==0x81 and 0xB8<=d[i+1]<=0xBF:
        disp=struct.unpack_from('<I',d,i+2)[0]
        if disp < 0x1000:
            offs[disp]+=1
print('  (offset, count) in the item-use function:')
for o_,n in sorted(offs.items(), key=lambda x:-x[1])[:14]:
    print('     [obj+0x%03X]  x%d' % (o_,n))
