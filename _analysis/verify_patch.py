# -*- coding: utf-8 -*-
"""Full verification of the patched EXE: end-to-end disasm of the cave, string
resolution, hook encoding, and a self-consistency check of every IAT reference."""
import struct, sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE, disasm, fmt
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

patched = r"D:\XiuXian\懒人修仙传.patched.exe"
orig = r"D:\XiuXian\懒人修仙传.exe"
HOOK_VA, CAVE_VA = 0x476FC7, 0x64462A

po, pp = PE(orig), PE(patched)
OUT = r"D:\XiuXian\_analysis\reports\verify_patch.txt"
f = io.StringIO()

# --- 1. confirm ONLY the intended bytes differ
diffs = []
for i in range(len(po.raw)):
    if po.raw[i] != pp.raw[i]:
        diffs.append(i)
runs = []
for off in diffs:
    if runs and off == runs[-1][1] + 1:
        runs[-1][1] = off
    else:
        runs.append([off, off])
f.write("### byte-diff runs: %d\n" % len(runs))
for a, b in runs:
    f.write("  file 0x%06X..0x%06X (len %d)  VA 0x%08X..0x%08X\n"
            % (a, b, b - a + 1, po.off2va(a), po.off2va(b)))
f.write("  total changed bytes: %d\n" % len(diffs))

# --- 2. hook encoding
f.write("\n### hook site\n")
hook_off = pp.va2off(HOOK_VA)
hb = pp.raw[hook_off:hook_off + 5]
tgt = HOOK_VA + 5 + struct.unpack("<i", hb[1:5])[0]
f.write("  bytes %s -> target 0x%08X (expect 0x%08X) %s\n"
        % (hb.hex(), tgt, CAVE_VA, "OK" if tgt == CAVE_VA else "BAD"))

# --- 3. cave: full disasm with IAT symbol names
iat = {"0x245728": "CreatePopupMenu", "0x245724": "AppendMenuW",
       "0x2457f0": "GetCursorPos", "0x245600": "GetForegroundWindow",
       "0x2455fc": "SetForegroundWindow", "0x245608": "TrackPopupMenu",
       "0x24556c": "DestroyMenu"}
f.write("\n### injected code at 0x%08X (full)\n" % CAVE_VA)
code = pp.raw[pp.va2off(CAVE_VA):pp.va2off(CAVE_VA) + 304]
md = Cs(CS_ARCH_X86, CS_MODE_32)
bad_iat = []
for ins in md.disasm(code, CAVE_VA):
    note = ""
    if "[ebx + 0x" in ins.op_str:
        key = "0x" + ins.op_str.split("[ebx + 0x")[1].rstrip("]")
        if ins.mnemonic in ("call", "jmp"):
            note = "   ; IAT " + iat.get(key, "UNKNOWN!")
            if key not in iat:
                bad_iat.append(key)
    if "lea edx, [ebx + 0x" in ins.op_str:
        rva = int(ins.op_str.split("[ebx + 0x")[1].rstrip("]"), 16)
        sva = IMAGE_BASE + rva
        try:
            s = pp.raw[pp.va2off(sva):pp.va2off(sva) + 12].decode("utf-16-le").split("\x00")[0]
        except Exception:
            s = "??"
        note = "   ; str 0x%08X = %r" % (sva, s)
    f.write("  0x%08X  %-20s %-30s %s%s\n" % (ins.address, ins.bytes.hex(),
                                               ins.mnemonic, ins.op_str, note))
f.write("  unknown IAT refs: %s\n" % (bad_iat or "none"))

# --- 4. the six strings must be the attribute names
f.write("\n### chooser strings\n")
for va in (0x6446F9, 0x6446FD, 0x644701, 0x644705, 0x644709, 0x64470D):
    raw = pp.raw[pp.va2off(va):pp.va2off(va) + 8]
    f.write("  0x%08X  %-20s %r\n" % (va, raw.hex(), raw.decode("utf-16-le").split("\x00")[0]))

# --- 5. downstream code after the hook must be intact
f.write("\n### original code after the hook (unchanged?)\n")
for va, b, m, o in disasm(po, 0x476FCC, 0x30):
    same = po.raw[po.va2off(va):po.va2off(va) + len(b)] == pp.raw[pp.va2off(va):pp.va2off(va) + len(b)]
    f.write("  0x%08X  %-20s %s %s   %s\n" % (va, b.hex(), m, o, "same" if same else "CHANGED"))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("verify written; diffs=%d runs=%d badIAT=%s" % (len(diffs), len(runs), bad_iat))
