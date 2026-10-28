# -*- coding: utf-8 -*-
"""Locate item-use dispatch by scanning .text for cmp-immediate on type1 values.
Read-only. Works strictly inside the workspace EXE."""
import struct

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\_analysis\reports\type_dispatch.txt"

raw = open(EXE, "rb").read()
pe = struct.unpack_from("<I", raw, 0x3c)[0]
nsec = struct.unpack_from("<H", raw, pe + 6)[0]
opt = pe + 24
sec = opt + struct.unpack_from("<H", raw, pe + 20)[0]

secs = []
for i in range(nsec):
    o = sec + i * 40
    nm = raw[o:o + 8].rstrip(b"\x00").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", raw, o + 8)
    secs.append((nm, va, vs, rp, rs))

tname, tva, tvs, trp, trs = [s for s in secs if s[0] == ".text"][0]
text = raw[trp:trp + trs]


def va_of(off):
    return tva + off


def find_all(buf, pat):
    out, st = [], 0
    while True:
        i = buf.find(pat, st)
        if i < 0:
            return out
        out.append(i)
        st = i + 1


TARGETS = [100, 105, 106, 107, 108, 110, 112, 113, 114, 115, 116, 117, 118, 119,
           120, 121, 122, 123, 124, 126, 127, 128, 129, 130, 131, 132,
           200, 201, 202, 203, 204, 300, 302, 303]

regs = {0xF8: "eax", 0xF9: "ecx", 0xFA: "edx", 0xFB: "ebx",
        0xFC: "esp", 0xFD: "ebp", 0xFE: "esi", 0xFF: "edi"}

# For each target, collect all comparison sites; report clusters (a jump table
# or cmp chain shows as many sites packed close together in one function).
per_target = {}
for t in TARGETS:
    sites = []
    tb = t.to_bytes(4, "little")
    if t < 128:
        for mod in regs:
            sites += [(i, "83/%s" % regs[mod]) for i in find_all(text, bytes([0x83, mod, t]))]
    for mod in regs:
        sites += [(i, "81/%s" % regs[mod]) for i in find_all(text, bytes([0x81, mod]) + tb)]
    sites += [(i, "3D/eax") for i in find_all(text, b"\x3d" + tb)]
    per_target[t] = sites

# Cluster detection: find the densest 4KB window covering the most distinct targets
best = None
step = 0x400
for start in range(0, len(text) - step, step):
    ws = set()
    for t, sites in per_target.items():
        for off, _ in sites:
            if start <= off < start + step:
                ws.add(t)
                break
    if best is None or len(ws) > best[0]:
        best = (len(ws), start, set(ws))

lines = []
lines.append("PE sections:")
for nm, va, vs, rp, rs in secs:
    lines.append("  %-8s va=0x%-8X vsize=0x%-8X rawptr=0x%-8X rawsize=0x%-8X"
                 % (nm, va, vs, rp, rs))
lines.append("")
lines.append("Total cmp-immediate sites found across type1 targets:")
for t in TARGETS:
    lines.append("  type1=%-5d sites=%d  vaddrs=%s"
                 % (t, len(per_target[t]),
                    [hex(va_of(o)) for o, _ in per_target[t][:6]]))

if best:
    lines.append("")
    lines.append("Densest 0x%X-byte window in .text: file off 0x%X (va 0x%X)"
                 % (step, best[1], va_of(best[1])))
    lines.append("  distinct type1 constants present: %s" % sorted(best[2]))
    lines.append("  count=%d" % best[0])

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("\n".join(lines))
