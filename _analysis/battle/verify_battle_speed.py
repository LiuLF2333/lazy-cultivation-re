# -*- coding: utf-8 -*-
"""Verify the battle-speed patch: byte diff, PE headers, section flags, code."""
import hashlib
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

A = r"D:\XiuXian\懒人修仙传.exe"
B = r"D:\XiuXian\懒人修仙传.speed.exe"

md = Cs(CS_ARCH_X86, CS_MODE_32)
pa, pb = PE(A), PE(B)
a, b = pa.raw, pb.raw

print("size  %d -> %d (%s)" % (len(a), len(b), "same" if len(a) == len(b) else "CHANGED"))
print("sha256 A", hashlib.sha256(a).hexdigest())
print("sha256 B", hashlib.sha256(b).hexdigest())

diffs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
print("differing bytes:", len(diffs))
runs = []
for i in diffs:
    if runs and i == runs[-1][1] + 1:
        runs[-1][1] = i
    else:
        runs.append([i, i])
for s, e in runs:
    va = pa.off2va(s)
    print("  file 0x%06X-0x%06X va 0x%08X  %s -> %s"
          % (s, e, va if va else -1, a[s:e + 1].hex(" "), b[s:e + 1].hex(" ")))

print("\nPE headers identical except section flags:",
      bytes(a[:pa.sections[0]["rawptr"]]) != bytes(b[:pb.sections[0]["rawptr"]]))
for sa, sb in zip(pa.sections, pb.sections):
    if sa["chars"] != sb["chars"]:
        print("  %-8s chars 0x%08X -> 0x%08X  (W flag added: %s)"
              % (sa["name"], sa["chars"], sb["chars"], bool(sb["chars"] & 0x80000000)))
print("  section raw/virtual layout identical:",
      all((x["va"], x["vsize"], x["rawptr"]) == (y["va"], y["vsize"], y["rawptr"])
          for x, y in zip(pa.sections, pb.sections)))


def show(va_from, va_to, label):
    print("\n--- %s ---" % label)
    o = pb.va2off(va_from)
    for ins in md.disasm(b[o:o + (va_to - va_from)], va_from):
        tgt = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            tgt = "  -> 0x%X" % int(ins.op_str, 16)
        print("  %08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, tgt))


show(0x48AB36, 0x48AB4A, "1. wait branch (0x48AB42)")
show(0x4C5D60, 0x4C5D72, "2. burst hook (0x4C5D66)")
show(0x4C5CA0, 0x4C5CB8, "3. log gate (0x4C5CAA)")
show(0x703E18, 0x703E91, "4. caves")

o = pb.va2off(0x4C5D66)
rel = struct.unpack_from("<i", b, o + 1)[0]
print("\nburst hook target: 0x%08X (expect 0x703E18)" % (0x4C5D66 + 5 + rel))
o = pb.va2off(0x4C5CAA)
rel = struct.unpack_from("<i", b, o + 1)[0]
print("log   hook target: 0x%08X (expect 0x703E6A)" % (0x4C5CAA + 5 + rel))
print("0x4C2AA0 untouched:",
      b[pb.va2off(0x4C2AA0):pb.va2off(0x4C2AA0) + 5].hex(" ") == "e8 0b 80 fc ff")
print("flag slot 0x703EF0..0x703EF4 differs from original:",
      a[pa.va2off(0x703EF0):pa.va2off(0x703EF0) + 4].hex(),
      "->", b[pb.va2off(0x703EF0):pb.va2off(0x703EF0) + 4].hex(),
      "(runtime state, zero on disk)")
