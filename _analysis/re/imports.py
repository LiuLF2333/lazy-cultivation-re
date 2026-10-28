import struct, sys, re, collections
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH

p = PE(PATH)
d = p.data

# ---------- Imports ----------
imp_rva, imp_sz = p.dd[1]
off = p.rva2off(imp_rva)
print('=== IMPORT DESCRIPTORS (file offset 0x%X) ===' % off)
imps = []
i = 0
while True:
    ent = d[off+i*20: off+i*20+20]
    oft, ts, fc, namerva, firstthunk = struct.unpack('<IIIII', ent)
    if namerva == 0 and firstthunk == 0: break
    noff = p.rva2off(namerva)
    name = d[noff:d.index(b'\0', noff)].decode('latin1')
    # thunks
    toff = p.rva2off(oft) if oft else p.rva2off(firstthunk)
    funcs = []
    j = 0
    while True:
        v = struct.unpack_from('<I', d, toff + j*4)[0]
        if v == 0: break
        if v & 0x80000000:
            funcs.append('ORD_%d' % (v & 0xFFFF))
        else:
            fo = p.rva2off(v)
            fn = d[fo+2: d.index(b'\0', fo+2)].decode('latin1')
            funcs.append(fn)
        j += 1
    imps.append((name, funcs))
    print('\n--- %s  (%d imports)  dsc@0x%X IATrva=0x%X ---' % (name, len(funcs), off+i*20, firstthunk))
    for k in range(0, len(funcs), 6):
        print('   ', ' '.join(funcs[k:k+6]))
    i += 1

print()
allnames = set()
for n, f in imps: allnames.update(f)

print('=== Delay imports ===')
dimp_rva, dimp_sz = p.dd[13]
if dimp_rva:
    print('present RVA=0x%X size=%d' % (dimp_rva, dimp_sz))
else:
    print('none')
