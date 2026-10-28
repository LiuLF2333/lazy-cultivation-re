import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data

rva,sz = p.dd[2]
base = p.rva2off(rva)

def read_dir(off, path, out):
    nname, nid = struct.unpack_from('<HH', d, off+12)
    for i in range(nname+nid):
        eo = off + 16 + i*8
        nid_or_name, dataoff = struct.unpack_from('<II', d, eo)
        if nid_or_name & 0x80000000:
            no = base + (nid_or_name & 0x7FFFFFFF)
            ln = struct.unpack_from('<H', d, no)[0]
            nm = d[no+2:no+2+ln*2].decode('utf-16-le', errors='replace')
        else:
            nm = nid_or_name
        if dataoff & 0x80000000:
            read_dir(base + (dataoff & 0x7FFFFFFF), path+[nm], out)
        else:
            de = base + dataoff
            drva, dsz, cp, res = struct.unpack_from('<IIII', d, de)
            out.append((path+[nm], drva, dsz, cp, p.rva2off(drva)))
    return out

tree = []
read_dir(base, [], tree)
DLG = {}
for path, drva, dsz, cp, off in tree:
    if path[0] == 5 and len(path) == 3:
        DLG[path[1]] = (off, dsz)

# ---- DIALOG template parser (standard DLGTEMPLATE, possibly DLGTEMPLATEEX) ----
def parse_dialog(off, size):
    end = off + size
    ver, sig = struct.unpack_from('<HH', d, off)
    ex = (ver == 1 and sig == 0xFFFF)
    o = off
    if ex:
        o += 2
        (helpid, exstyle, style, dwexstyle, cdit, x, y, cx, cy) = struct.unpack_from('<IHHIHhhhh', d, o); o += 24
    else:
        (style, exstyle, cdit, x, y, cx, cy) = struct.unpack_from('<IIHhhhh', d, o); o += 18
    def read_sz(o):
        # menu / class / title: 0x0000 = none, 0xFFFF = ordinal follows
        v = struct.unpack_from('<H', d, o)[0]
        if v == 0x0000: return o+2, None
        if v == 0xFFFF: return o+4, ('ORD', struct.unpack_from('<H', d, o+2)[0])
        s = []
        while True:
            c = struct.unpack_from('<H', d, o)[0]
            if c == 0: break
            s.append(chr(c)); o += 2
        return o+2, ''.join(s)
    o, menu = read_sz(o)
    o, cls = read_sz(o)
    o, title = read_sz(o)
    # alignment if ex and style has DS_SETFONT -> extra fields
    if ex and (style & 0x40):
        pts, wt, ital, charset = struct.unpack_from('<HhhB', d, o); o += 7
        o, fontname = read_sz(o)
    elif not ex and (style & 0x40):
        pts = struct.unpack_from('<H', d, o)[0]; o += 2
        o, fontname = read_sz(o)
    ctrls = []
    for i in range(cdit):
        o = (o + 3) & ~3
        if ex:
            # helpID(DWORD) exStyle(DWORD) style(DWORD) x,y,cx,cy(short) id(DWORD)
            (chelpid, cexstyle, cstyle, cx, cy, ccx, ccy, cid) = struct.unpack_from('<IIIhhhhI', d, o); o += 24
        else:
            (cstyle, cexstyle, cx, cy, ccx, ccy, cid) = struct.unpack_from('<IIhhhhH', d, o); o += 18
        o, ccls = read_sz(o)
        o, ctext = read_sz(o)
        extra = struct.unpack_from('<H', d, o)[0]
        o += 2 + extra
        ctrls.append((cid, ccls, ctext, cstyle, cx, cy, ccx, ccy))
    return dict(ex=ex, title=title, cls=cls, style=style, cdit=cdit, cx=cx, cy=cy, ctrls=ctrls)

print('=== DIALOG RESOURCES (%d) ===' % len(DLG))
for did in sorted(DLG):
    off, size = DLG[did]
    try:
        info = parse_dialog(off, size)
    except Exception as e:
        print('  dlg %-6s PARSE ERROR %s' % (did, e)); continue
    print('-'*78)
    print('DIALOG %s  file=0x%X size=%d  ex=%s  title=%r class=%r style=0x%X  client=%dx%d  controls=%d' % (
        did, off, size, info['ex'], info['title'], info['cls'], info['style'], info['cx'], info['cy'], info['cdit']))
    for cid, ccls, ctext, cstyle, x, y, cx, cy in info['ctrls']:
        print('    id=%-6s class=%-22s rect=(%d,%d,%dx%d) text=%r' % (cid, ccls, x, y, cx, cy, ctext))
