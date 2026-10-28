# -*- coding: utf-8 -*-
"""Minimal x86 assembler + PE patcher infrastructure.

No MSVC/nasm/keystone is available on this machine, and Python has neither
keystone nor pefile, so this module hand-encodes the handful of instruction
forms the patch needs and writes them into the PE.

Design constraints discovered from the binary:
  * ImageBase 0x400000, DllCharacteristics has DYNAMIC_BASE (ASLR) set.
  * .text has exactly ONE usable code cave: VA 0x64462A, 470 bytes of 0x00.
  * Adding a new section would require updating SizeOfImage and losing Steam
    hash-stability; the cave is preferred.
  * Injected code must be POSITION-INDEPENDENT: ASLR relocates the image, so
    any absolute address baked into new code would break. We therefore only
    use RIP-free, EBP-relative addressing and rel32 CALL/JMP, which the loader
    relocates correctly *only if* we add .reloc entries. To avoid touching
    .reloc, we reference globals exclusively through rel32 CALL/JMP to existing
    code and through EBP-relative stack slots, never absolute disp32 data refs.
    (Verified: an absolute `mov eax,[0x6c8878]` in a cave would NOT be
    relocated, because the loader only applies .reloc entries that exist.)
"""
import struct

IMAGE_BASE = 0x400000

# ---------------------------------------------------------------- encoding


def rel32(from_va, to_va):
    """rel32 for a call/jmp whose next instruction starts at from_va+5."""
    d = to_va - (from_va + 5)
    if not (-0x80000000 <= d <= 0x7FFFFFFF):
        raise ValueError("rel32 out of range")
    return struct.pack("<i", d)


class Asm:
    """Tiny accumulator that tracks the current VA as it emits."""

    def __init__(self, va):
        self.va = va
        self.buf = bytearray()
        self.fixups = []          # (offset_in_buf, target_hint)

    # -- core emit
    def emit(self, b):
        self.buf += b
        self.va += len(b)
        return self

    def label_here(self):
        return self.va

    # -- push / pop
    def push_r(self, r):
        return self.emit(bytes([0x50 + r]))

    def pop_r(self, r):
        return self.emit(bytes([0x58 + r]))

    def push_imm32(self, v):
        return self.emit(b"\x68" + struct.pack("<I", v & 0xFFFFFFFF))

    # -- mov
    def mov_r_imm32(self, r, v):
        return self.emit(bytes([0xB8 + r]) + struct.pack("<I", v & 0xFFFFFFFF))

    def mov_r_rm(self, dst, base, disp=0, size=4):
        """mov dst, [base+disp]"""
        modrm = 0x80 | ((dst & 7) << 3) | (base & 7)
        if base & 7 == 4:
            raise ValueError("esp base needs SIB; use mov_r_rm_sib")
        if size == 4:
            return self.emit(b"\x8B" + bytes([modrm]) + struct.pack("<i", disp))
        if size == 1:
            return self.emit(b"\x0F\xB6" + bytes([modrm]) + struct.pack("<i", disp))
        raise ValueError("size")

    def mov_rm_r(self, base, src, disp=0, size=4):
        """mov [base+disp], src"""
        modrm = 0x80 | ((src & 7) << 3) | (base & 7)
        if base & 7 == 4:
            raise ValueError("esp base needs SIB")
        if size == 4:
            return self.emit(b"\x89" + bytes([modrm]) + struct.pack("<i", disp))
        if size == 1:
            return self.emit(b"\x88" + bytes([modrm]) + struct.pack("<i", disp))
        raise ValueError("size")

    def lea(self, dst, base, disp=0):
        modrm = 0x80 | ((dst & 7) << 3) | (base & 7)
        if base & 7 == 4:
            raise ValueError("esp base needs SIB")
        return self.emit(b"\x8D" + bytes([modrm]) + struct.pack("<i", disp))

    # -- arithmetic (reg, imm32)
    def add_r_imm32(self, r, v):
        return self.emit(b"\x81" + bytes([0xC0 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def sub_r_imm32(self, r, v):
        return self.emit(b"\x81" + bytes([0xE8 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def cmp_r_imm32(self, r, v):
        return self.emit(b"\x81" + bytes([0xF8 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def cmp_r_imm8(self, r, v):
        return self.emit(b"\x83" + bytes([0xF8 | (r & 7)]) + struct.pack("<b", v))

    # -- logic / test
    def xor_r_r(self, dst, src):
        return self.emit(b"\x33" + bytes([0xC0 | ((dst & 7) << 3) | (src & 7)]))

    def test_r_r(self, a, b):
        return self.emit(b"\x85" + bytes([0xC0 | ((b & 7) << 3) | (a & 7)]))

    # -- calls / jumps
    def call_abs(self, target_va):
        """E8 rel32 - relocated by the loader only if a .reloc entry exists;
        for targets inside the same image we add the reloc ourselves."""
        off = len(self.buf)
        self.emit(b"\xE8" + rel32(self.va, target_va))
        self.fixups.append((off + 1, target_va, "rel32"))
        return self

    def jmp_abs(self, target_va):
        self.emit(b"\xE9" + rel32(self.va, target_va))
        return self

    def jmp_short(self, delta):
        return self.emit(b"\xEB" + struct.pack("<b", delta))

    def je_short(self, delta):
        return self.emit(b"\x74" + struct.pack("<b", delta))

    def jne_short(self, delta):
        return self.emit(b"\x75" + struct.pack("<b", delta))

    def jl_short(self, delta):
        return self.emit(b"\x7C" + struct.pack("<b", delta))

    def jge_short(self, delta):
        return self.emit(b"\x7D" + struct.pack("<b", delta))

    def jle_short(self, delta):
        return self.emit(b"\x7E" + struct.pack("<b", delta))

    def jg_short(self, delta):
        return self.emit(b"\x7F" + struct.pack("<b", delta))

    def ret(self):
        return self.emit(b"\xC3")

    def int3(self, n=1):
        return self.emit(b"\xCC" * n)

    def nop(self, n=1):
        return self.emit(b"\x90" * n)

    def bytes_(self):
        return bytes(self.buf)


# ---------------------------------------------------------------- PE writing

class PeWriter:
    def __init__(self, path):
        self.path = path
        self.raw = bytearray(open(path, "rb").read())
        pe = struct.unpack_from("<I", self.raw, 0x3C)[0]
        self.pe_off = pe
        nsec = struct.unpack_from("<H", self.raw, pe + 6)[0]
        opt = pe + 24
        self.opt = opt
        sizeopt = struct.unpack_from("<H", self.raw, pe + 20)[0]
        sec = opt + sizeopt
        self.sections = []
        for i in range(nsec):
            o = sec + i * 40
            name = bytes(self.raw[o:o + 8]).rstrip(b"\x00").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", self.raw, o + 8)
            self.sections.append(dict(hdr=o, name=name, va=vaddr, vsize=vsize,
                                      rawptr=rawptr, rawsize=rawsize))
        self.sizeopt = sizeopt

    def sec(self, name):
        return [s for s in self.sections if s["name"] == name][0]

    def va2off(self, va):
        rva = va - IMAGE_BASE
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["rawptr"] + (rva - s["va"])
        return None

    def off2va(self, off):
        for s in self.sections:
            if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
                return IMAGE_BASE + s["va"] + (off - s["rawptr"])
        return None

    def write_at_va(self, va, data):
        o = self.va2off(va)
        if o is None:
            raise ValueError("VA 0x%X not mapped" % va)
        self.raw[o:o + len(data)] = data

    def read_at_va(self, va, n):
        o = self.va2off(va)
        return bytes(self.raw[o:o + n])

    def save(self, out_path):
        open(out_path, "wb").write(bytes(self.raw))
