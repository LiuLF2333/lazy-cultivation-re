# -*- coding: utf-8 -*-
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = PE(r"D:\XiuXian\懒人修仙传.exe")
md = Cs(CS_ARCH_X86, CS_MODE_32)

imp_rva, imp_sz = struct.unpack_from("<II", pe.raw, pe.opt + 96 + 8 * 1)
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
            fn = pe.raw[no + 2:].split(b"\x00")[0].decode("latin1")
            name2slot[IMAGE_BASE + firstThunk + (j - thunk)] = dll + "!" + fn
        j += 4
    i += 20


def dis(start, nbytes, title=""):
    out = ["", "==== %s  VA 0x%08X (%d bytes) ====" % (title, start, nbytes)]
    off = pe.va2off(start)
    code = pe.raw[off:off + nbytes]
    for ins in md.disasm(code, start):
        note = ""
        op = ins.op_str
        if op.startswith("dword ptr [0x"):
            try:
                va = int(op.split("[0x")[1].split("]")[0], 16)
            except ValueError:
                va = None
            if va in name2slot:
                note = "   ; " + name2slot[va]
        out.append("  0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, op, note))
    return "\n".join(out)


txt = []
txt.append(dis(0x476740, 0x70, "type1=110 item-use handler prologue"))
txt.append(dis(0x476F80, 0x60, "around the hook 0x476FC7"))
txt.append(dis(0x4219B0, 0x90, "0x4219B0 (format entry)"))
txt.append(dis(0x4041A0, 0x40, "0x4041A0"))
txt.append(dis(0x40A480, 0x40, "0x40A480 (CString ctor?)"))
txt.append(dis(0x4065E0, 0x40, "0x4065E0"))
txt.append(dis(0x40A560, 0x40, "0x40A560"))
txt.append(dis(0x421360, 0x60, "0x421360"))
txt.append(dis(0x421670, 0x30, "0x421670"))
txt.append(dis(0x4AE93C, 0xC0, "version chooser result region"))
open(r"D:\XiuXian\_analysis\reports\chooser_dump2.txt", "w", encoding="utf-8").write("\n".join(txt))
print("ok")
