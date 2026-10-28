import struct
import sys

PATH = r"D:\XiuXian\懒人修仙传.exe.bak.20261019-193436-571623"
d = open(PATH, "rb").read()
OFF = 0x2C51B0
SIZE = 1648
end = OFF + SIZE


def u16(o):
    return struct.unpack_from("<H", d, o)[0]


def read_sz(o):
    v = u16(o)
    if v == 0:
        return o + 2, None
    if v == 0xFFFF:
        return o + 4, ("ORD", u16(o + 2))
    s = []
    while True:
        c = u16(o)
        if c == 0:
            break
        s.append(chr(c))
        o += 2
    return o + 2, "".join(s)


o = OFF
ver, sig = struct.unpack_from("<HH", d, o)
o += 4
ex = (ver == 1 and sig == 0xFFFF)
if ex:
    helpid, exstyle, style, cdit, x, y, cx, cy = struct.unpack_from("<IIIHhhhh", d, o)
    o += 22
else:
    style, exstyle, cdit, x, y, cx, cy = struct.unpack_from("<IIHhhhh", d, o)
    o += 18
o, menu = read_sz(o)
o, cls = read_sz(o)
o, title = read_sz(o)
if style & 0x40:
    if ex:
        pts, weight, italic, charset = struct.unpack_from("<HHBB", d, o)
        o += 6
    else:
        pts = u16(o)
        o += 2
    o, font = read_sz(o)
else:
    pts = weight = italic = charset = None
    font = None

print("ex=%s style=0x%08X exstyle=0x%08X cdit=%d client=%dx%d title=%r class=%r" % (
    ex, style, exstyle, cdit, cx, cy, title, cls))
print("font=%r pts=%r weight=%r italic=%r charset=%r" % (font, pts, weight, italic, charset))

for i in range(cdit):
    o = (o + 3) & ~3
    if ex:
        chelpid, cexstyle, cstyle, x, y, ccx, ccy, cid = struct.unpack_from("<IIIhhhhI", d, o)
        o += 24
    else:
        cstyle, cexstyle, x, y, ccx, ccy, cid = struct.unpack_from("<IIhhhhH", d, o)
        o += 18
    o, ccls = read_sz(o)
    o, ctext = read_sz(o)
    extra = u16(o)
    o += 2 + extra
    print("ctrl %-2d id=%-6d class=%-10r style=0x%08X ex=0x%08X rect=(%d,%d,%dx%d) text=%r" % (
        i, cid, ccls, cstyle, cexstyle, x, y, ccx, ccy, ctext))

print("parsed to 0x%X (end 0x%X), trailing=%r" % (o, end, d[o:end]))
