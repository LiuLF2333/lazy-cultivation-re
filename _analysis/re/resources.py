import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data

RT = {1:'CURSOR',2:'BITMAP',3:'ICON',4:'MENU',5:'DIALOG',6:'STRING',7:'FONTDIR',8:'FONT',
      9:'ACCELERATOR',10:'RCDATA',11:'MESSAGETABLE',12:'GROUP_CURSOR',14:'GROUP_ICON',
      16:'VERSION',17:'DLGINCLUDE',19:'PLUGPLAY',20:'VXD',21:'ANICURSOR',22:'ANIICON',
      23:'HTML',24:'MANIFEST'}

rva,sz = p.dd[2]
base = p.rva2off(rva)
print('Resource dir RVA=0x%X size=%d file=0x%X' % (rva, sz, base))

def read_dir(off, level, path, out):
    nname, nid = struct.unpack_from('<HH', d, off+12)
    entries = []
    for i in range(nname+nid):
        eo = off + 16 + i*8
        nid_or_name, dataoff = struct.unpack_from('<II', d, eo)
        entries.append((nid_or_name, dataoff))
    for nid_or_name, dataoff in entries:
        if nid_or_name & 0x80000000:
            no = base + (nid_or_name & 0x7FFFFFFF)
            ln = struct.unpack_from('<H', d, no)[0]
            nm = d[no+2:no+2+ln*2].decode('utf-16-le', errors='replace')
        else:
            nm = nid_or_name
        if dataoff & 0x80000000:
            read_dir(base + (dataoff & 0x7FFFFFFF), level+1, path+[nm], out)
        else:
            de = base + dataoff
            drva, dsz, cp, res = struct.unpack_from('<IIII', d, de)
            out.append((path+[nm], drva, dsz, cp, p.rva2off(drva)))

tree = []
read_dir(base, 0, [], tree)

# aggregate by top-level type
bytype = collections.defaultdict(list)
for path, drva, dsz, cp, off in tree:
    t = path[0]
    tname = RT.get(t, str(t)) if isinstance(t,int) else t
    bytype[tname].append((path, drva, dsz, cp, off))

print()
print('=== RESOURCE TYPES ===')
for t, items in sorted(bytype.items(), key=lambda x:-len(x[1])):
    print('  %-14s %4d entries   total %d bytes' % (t, len(items), sum(i[2] for i in items)))

print()
print('=== DIALOG resources (type 5) ===')
dlg = bytype.get('DIALOG', [])
for path, drva, dsz, cp, off in dlg:
    print('  id=%-8s rva=0x%06X size=%-6d cp=%d off=0x%06X' % (path[1], drva, dsz, cp, off))
print('  count:', len(dlg))

print()
print('=== All resource IDs grouped (top types) ===')
for t in ['DIALOG','MENU','ICON','BITMAP','STRING','RCDATA','VERSION','GROUP_ICON','MANIFEST','FONT','ACCELERATOR','GROUP_CURSOR','CURSOR']:
    if t in bytype:
        ids = [str(i[0][1]) for i in bytype[t]]
        print('  %-12s (%d): %s' % (t, len(ids), ', '.join(ids[:60]) + (' ...' if len(ids)>60 else '')))

# save full tree
with open(r"D:\XiuXian\_analysis\re\out\resources.txt",'w',encoding='utf-8') as f:
    f.write('type\tid\tlang\trva\tsize\tcodepage\tfileoffset\n')
    for path, drva, dsz, cp, off in tree:
        f.write('%s\t%s\t%s\t0x%06X\t%d\t%d\t0x%06X\n' % (
            RT.get(path[0],path[0]) if isinstance(path[0],int) else path[0],
            path[1] if len(path)>1 else '', path[2] if len(path)>2 else '',
            drva, dsz, cp, off or 0))
print()
print('saved resources.txt (%d entries)' % len(tree))
