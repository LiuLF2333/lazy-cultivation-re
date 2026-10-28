# -*- coding: utf-8 -*-
"""Decode the six injected chooser strings from the patched EXE and confirm the
hook, cave bounds, and that the file is otherwise byte-identical to the
original outside [hook, cave]."""
import io, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

orig = PE(r"D:\XiuXian\懒人修仙传.exe")
pat = PE(r"D:\XiuXian\懒人修仙传.patched.exe")
OUT = r"D:\XiuXian\_analysis\reports\final_check.txt"
f = io.StringIO()

f.write("### injected chooser strings (UTF-16LE)\n")
for rva in (0x244748, 0x24474E, 0x244754, 0x24475A, 0x244760, 0x244766):
    va = IMAGE_BASE + rva
    raw = pat.raw[pat.va2off(va):pat.va2off(va) + 8]
    s = raw.decode("utf-16-le").split("\x00")[0]
    f.write("  VA 0x%08X = %r  (%s)\n" % (va, s, raw.hex()))

f.write("\n### hook\n")
ho = pat.va2off(0x476FC7)
hb = pat.raw[ho:ho + 5]
f.write("  bytes %s -> 0x%08X\n" % (hb.hex(), 0x476FC7 + 5 + struct.unpack("<i", hb[1:5])[0]))

f.write("\n### differences restricted to the two intended regions?\n")
CAVE_VA = 0x64462A
code_len = 0x644748 - CAVE_VA          # code part before the strings
cave_bytes = 0x644748 - CAVE_VA + 6 * 10
o_hook = orig.va2off(0x476FC7)
o_cave = orig.va2off(CAVE_VA)
bad = 0
for i in range(len(orig.raw)):
    if orig.raw[i] == pat.raw[i]:
        continue
    in_hook = o_hook <= i < o_hook + 5
    in_cave = o_cave <= i < o_cave + cave_bytes
    if not (in_hook or in_cave):
        bad += 1
        if bad <= 5:
            f.write("  UNEXPECTED diff at file 0x%06X VA 0x%08X\n" % (i, orig.off2va(i)))
f.write("  unexpected diffs: %d\n" % bad)
f.write("  cave region used: %d bytes of the 470 available (code %d + strings %d)\n"
        % (cave_bytes, code_len, 6 * 10))

f.write("\n### cave availability\n")
f.write("  bytes needed: %d ; cave size: 470 ; fits: %s\n"
        % (cave_bytes, cave_bytes <= 470))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("bad=%d need=%d" % (bad, cave_bytes))
