import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS, TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']

ITEMTYPES = set([100,105,106,107,108,110,112,113,114,115,116,117,118,119,120,123,127,129,130,131,132,
                 200,201,202,203,204,300,302,303])

def off2va(o): 
    r = p.off2rva(o)
    return None if r is None else r + p.image_base
def va2off(v):
    return p.rva2off(v - p.image_base)

# ---- find switch jump tables: FF 24 85/8D/95/9D/B5 <imm32>  (jmp [reg*4+imm32]) ----
SCALE = {0x85:'eax', 0x8D:'ecx', 0x95:'edx', 0x9D:'ebx', 0xB5:'ebp'}
found = []
for i in range(TS, TE-6):
    if d[i] == 0xFF and d[i+1] in SCALE and d[i+2] in (0x85,0x8D,0x95,0x9D,0xB5):
        # FF 24 <modrm> <imm32> ; modrm = 0x85 | (idx<<3) => 24 85 = [eax*4+disp32]
        if d[i+1] == 0x24:
            tbl = struct.unpack_from('<I', d, i+3)[0]
            found.append((i, SCALE[d[i+2]], tbl))

print('jmp [reg*4+disp32] switch tables found: %d' % len(found))
print()
# ---- decode each table, look for item-type codes ----
cands = []
for (site, reg, tbl) in found:
    to = va2off(tbl)
    if to is None or not (0 <= to < len(d)-4*300): continue
    vals = []
    for k in range(300):
        v = struct.unpack_from('<I', d, to+4*k)[0]
        if v == 0: break
        vals.append(v)
    if len(vals) < 3: continue
    voffs = [va2off(v) for v in vals]
    if any(o is None for o in voffs): continue
    # heuristic: does the earlier code compare against a range covering item types?
    score = sum(1 for o in voffs if TS <= o < TE)
    if score == len(vals):
        cands.append((site, reg, tbl, to, vals, voffs))

print('validated tables: %d' % len(cands))
print()
for site, reg, tbl, to, vals, voffs in cands:
    span = max(vals) - min(vals)
    print('table@file0x%06X rva0x%06X  site=0x%06X idx=%s  cases=%d  targetRVA span 0x%X..0x%X' % (
        to, tbl-p.image_base, site, reg, len(vals), min(vals)-p.image_base, max(vals)-p.image_base))
