# -*- coding: utf-8 -*-
"""Final audit: frame-slot usage must not overlap, every call must balance its
stack arguments, and the cave must sit inside the mapped .text page."""
import io, re, struct, sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pat = PE(r"D:\XiuXian\懒人修仙传.patched.exe")
CAVE_VA, CODE_LEN, STR_VA = 0x64462A, 0x11E, 0x644748
OUT = r"D:\XiuXian\_analysis\reports\audit.txt"
f = io.StringIO()

md = Cs(CS_ARCH_X86, CS_MODE_32)
code = pat.raw[pat.va2off(CAVE_VA):pat.va2off(CAVE_VA) + CODE_LEN]

# --- frame slot audit
slots = {}
md2 = Cs(CS_ARCH_X86, CS_MODE_32)
for ins in md2.disasm(code, CAVE_VA):
    m = re.findall(r"\[ebp - (0x[0-9a-f]+)\]", ins.op_str)
    for s in m:
        w = 4
        if "dword" in ins.op_str and ins.mnemonic in ("mov", "push"):
            w = 4
        slots.setdefault(s, []).append((ins.address, ins.mnemonic, ins.op_str, w))
f.write("### [ebp-x] slots referenced\n")
for s in sorted(slots, key=lambda x: int(x, 16)):
    off = int(s, 16)
    f.write("  %s (%d) used by:\n" % (s, off))
    for a, mn, op, w in slots[s]:
        f.write("     0x%08X  %s %s\n" % (a, mn, op))
f.write("\n  NOTE: POINT occupies [-0x20]..[-0x19]; declared slots must not overlap it.\n")

# --- stack-arg balance for each call dword ptr [ebx+...]
f.write("\n### per-call stack argument counts (pushed immediately before)\n")
insns = list(md.disasm(code, CAVE_VA))
pending = 0
for i, ins in enumerate(insns):
    if ins.mnemonic == "push":
        pending += 1
    elif ins.mnemonic == "call" and "[ebx +" in ins.op_str:
        api = {0x245728: "CreatePopupMenu", 0x245724: "AppendMenuW",
               0x2457f0: "GetCursorPos", 0x245600: "GetForegroundWindow",
               0x2456d8: "GetActiveWindow", 0x2455fc: "SetForegroundWindow",
               0x245608: "TrackPopupMenu", 0x24556c: "DestroyMenu"}.get(
                   int(ins.op_str.split("[ebx + 0x")[1].rstrip("]"), 16), "?")
        f.write("  0x%08X  %-18s pushes=%d\n" % (ins.address, api, pending))
        pending = 0
    elif ins.mnemonic in ("call",) or ins.mnemonic == "jmp":
        pending = 0

# --- cave inside the mapped page?
trp, tva, trs = pat.text()
f.write("\n### mapping\n")
f.write("  .text VA 0x%08X vsize 0x%X -> mapped end 0x%08X\n"
        % (IMAGE_BASE + tva, trs, IMAGE_BASE + tva + trs))
f.write("  cave 0x%08X..0x%08X sits %d bytes past VirtualSize, inside mapped page 0x%08X\n"
        % (CAVE_VA, CAVE_VA + 346, CAVE_VA - (IMAGE_BASE + tva + trs),
           CAVE_VA & ~0xFFF))

# --- round-trip the whole entry point
f.write("\n### entry sequence\n")
for ins in list(md.disasm(code, CAVE_VA))[:12]:
    f.write("  0x%08X  %-20s %s %s\n" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))

open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("audit written")
