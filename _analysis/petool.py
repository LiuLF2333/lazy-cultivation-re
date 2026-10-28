# -*- coding: utf-8 -*-
"""Correct PE32 address mapping + disassembly helpers for 懒人修仙传.exe.

The image base is 0x400000. NEVER mix raw file offsets with VAs:
    VA = ImageBase + SectionVA + (file_off - SectionRawPointer)
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
IMAGE_BASE = 0x400000


class PE:
    def __init__(self, path=EXE):
        self.path = path
        self.raw = open(path, "rb").read()
        raw = self.raw
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        self.pe_off = pe
        self.machine, self.nsec = struct.unpack_from("<HH", raw, pe + 4)
        opt = pe + 24
        self.opt = opt
        self.magic = struct.unpack_from("<H", raw, opt)[0]
        sizeopt = struct.unpack_from("<H", raw, pe + 20)[0]
        sec = opt + sizeopt
        self.sections = []
        for i in range(self.nsec):
            o = sec + i * 40
            name = raw[o:o + 8].rstrip(b"\x00").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, o + 8)
            chars = struct.unpack_from("<I", raw, o + 36)[0]
            self.sections.append(dict(name=name, va=vaddr, vsize=vsize,
                                      rawptr=rawptr, rawsize=rawsize, chars=chars))
        self.sizeopt = sizeopt

    # ---- address conversion ----
    def sec_of_va(self, va):
        rva = va - IMAGE_BASE
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s
        return None

    def va2off(self, va):
        s = self.sec_of_va(va)
        if s is None:
            return None
        off = s["rawptr"] + (va - IMAGE_BASE - s["va"])
        if off < 0 or off >= len(self.raw):
            return None
        return off

    def off2va(self, off):
        for s in self.sections:
            if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
                return IMAGE_BASE + s["va"] + (off - s["rawptr"])
        return None

    # ---- data reading ----
    def u32(self, va):
        o = self.va2off(va)
        if o is None:
            return None
        return struct.unpack_from("<I", self.raw, o)[0]

    def bytes_at(self, va, n):
        o = self.va2off(va)
        return self.raw[o:o + n]

    def wide(self, va, maxlen=400):
        """Read a NUL-terminated UTF-16LE string."""
        o = self.va2off(va)
        if o is None:
            return None
        out = []
        i = o
        while i + 1 < len(self.raw) and len(out) < maxlen:
            cp = self.raw[i] | (self.raw[i + 1] << 8)
            if cp == 0:
                break
            out.append(cp)
            i += 2
        if len(out) < 1:
            return None
        return bytes(b for cp in out for b in (cp & 0xFF, cp >> 8)).decode("utf-16-le", errors="replace")

    def cstr(self, va, maxlen=300):
        o = self.va2off(va)
        if o is None:
            return None
        j = o
        nb = []
        while j < len(self.raw) and self.raw[j] != 0 and len(nb) < maxlen:
            nb.append(self.raw[j])
            j += 1
        return bytes(nb).decode("gbk", errors="replace")

    def find_dword_va(self, value):
        """All VAs whose dword == value."""
        b = struct.pack("<I", value)
        out = []
        st = 0
        while True:
            i = self.raw.find(b, st)
            if i < 0:
                break
            va = self.off2va(i)
            if va is not None:
                out.append(va)
            st = i + 1
        return out

    def text(self):
        s = [x for x in self.sections if x["name"] == ".text"][0]
        return s["rawptr"], s["va"], s["rawsize"]

    def find_calls_to(self, target_va):
        """Linear sweep for E8 rel32 resolving to target_va (VAs)."""
        trp, tva, trs = self.text()
        text = self.raw[trp:trp + trs]
        hits = []
        for i in range(len(text) - 5):
            if text[i] != 0xE8:
                continue
            rel = struct.unpack_from("<i", text, i + 1)[0]
            site_va = IMAGE_BASE + tva + i
            if site_va + 5 + rel == target_va:
                hits.append(site_va)
        return hits

    def find_push_imm(self, value):
        """Sites pushing a 32-bit immediate (68 imm32 / 81 / 83 / cmp forms)."""
        trp, tva, trs = self.text()
        text = self.raw[trp:trp + trs]
        imm = struct.pack("<I", value)
        hits = []
        st = 0
        while True:
            i = text.find(imm, st)
            if i < 0:
                break
            if i >= 1 and text[i - 1] == 0x68:
                hits.append(IMAGE_BASE + tva + i - 1)
            st = i + 1
        return hits


_md = Cs(CS_ARCH_X86, CS_MODE_32)


def disasm(pe, start_va, nbytes, resync=True):
    """Linear sweep with optional resync; yields (va, bytes, mnemonic, op_str)."""
    off = pe.va2off(start_va)
    code = pe.raw[off:off + nbytes]
    pos = 0
    while pos < len(code):
        got = list(_md.disasm(code[pos:pos + 15], start_va + pos, count=1))
        if not got:
            if resync:
                yield (start_va + pos, code[pos:pos + 1], "db", "0x%02X" % code[pos])
                pos += 1
                continue
            return
        i = got[0]
        yield (i.address, i.bytes, i.mnemonic, i.op_str)
        pos += i.size


def fmt(ins):
    va, b, m, o = ins
    return "0x%08X  %-24s %s %s" % (va, b.hex(), m, o)


if __name__ == "__main__":
    pe = PE()
    print("image base 0x%X" % IMAGE_BASE)
    for s in pe.sections:
        print("  %-8s VA 0x%-8X vsize 0x%-8X rawptr 0x%-8X rawsize 0x%-8X"
              % (s["name"], IMAGE_BASE + s["va"], s["vsize"], s["rawptr"], s["rawsize"]))
    # sanity: verify known-good string
    print("\nsanity VA 0x68EDEC (expect 根骨[): %r" % pe.wide(0x68EDEC))
    print("sanity VA 0x67F734 (expect 选择让...): %r" % pe.wide(0x67F734))
    print("file 0x28EDEC -> VA 0x%X" % pe.off2va(0x28EDEC))
