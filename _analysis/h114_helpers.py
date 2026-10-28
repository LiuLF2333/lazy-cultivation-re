# -*- coding: utf-8 -*-
import struct, sys, io
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
md = Cs(CS_ARCH_X86, CS_MODE_32)
imp_rva, _ = struct.unpack_from("<II", pe.raw, pe.opt + 96 + 8 * 1)
imp_off = pe.va2off(IMAGE_BASE + imp_rva)
name2slot = {}
i = imp_off
while True:
    oft, ts, fc, nameRVA, firstThunk = struct.unpack_from("<IIIII", pe.raw, i)
    if nameRVA == 0:
        break
    dll = pe.raw[pe.va2off(IMAGE_BASE + nameRVA):].split(b"\x00")[0].decode("latin1")
    thunk = pe.va2off(IMAGE_BASE + firstThunk)
    j = thunk
    while True:
        ent = struct.unpack_from("<I", pe.raw, j)[0]
        if ent == 0:
            break
        if not (ent & 0x80000000):
            no = pe.va2off(IMAGE_BASE + ent)
            name2slot[IMAGE_BASE + firstThunk + (j - thunk)] = dll + "!" + pe.raw[no + 2:].split(b"\x00")[0].decode("latin1")
        j += 4
    i += 20

out = io.StringIO()
def dump(start, n, title):
    print("", file=out)
    print("==== %s VA 0x%08X ====" % (title, start), file=out)
    off = pe.va2off(start)
    if off is None:
        print("   <unmapped>", file=out); return
    for ins in md.disasm(pe.raw[off:off+n], start):
        note = ""
        if ins.op_str.startswith("dword ptr [0x"):
            try: va = int(ins.op_str.split("[0x")[1].split("]")[0], 16)
            except ValueError: va = None
            if va in name2slot: note = "   ; " + name2slot[va]
        print("  0x%08X  %-18s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, note), file=out)

dump(0x4CC988, 0x120, "0x4CC988 called at 114-handler start")
dump(0x4CFE86, 0x180, "0x4CFE86 called at 114-handler end (modal run?)")
dump(0x4D8595, 0x80, "0x4D8595 (create window)")
dump(0x40A290, 0x60, "0x40A290 widget create")
dump(0x40A200, 0x60, "0x40A200 setwindowtext?")
dump(0x40A110, 0x60, "0x40A110 sendmessage?")
open(r"D:\XiuXian\_analysis\reports\h114_helpers.txt", "w", encoding="utf-8").write(out.getvalue())
print("ok")
