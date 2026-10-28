# -*- coding: utf-8 -*-
"""Generate the patched 懒人修仙传.exe:
type1=110 random base-attribute pills now pop a chooser to pick the attribute.

Design:
  * Hook the single weighted-random call at VA 0x476FC7 (`call 0x41A120`) inside
    the 子分类==9 (=random attribute pill) block of the item-use function.
  * Redirect it (E8 rel32, position-independent) to injected code in the .text
    slack code cave at VA 0x64462A.
  * Injected code builds a Win32 popup menu with the six base-attribute names
    (根骨/真气/武术/灵力/灵巧/机缘) and calls TrackPopupMenu with TPM_RETURNCMD.
    Choosing entry i returns (i-1) => the original caller does `+1` to form the
    attribute id 1..6, exactly as the random path did.
  * Cancel (or any failure) falls back to the ORIGINAL 0x41A120 weighted random
    via a tail jump, so an item is never wasted and behaviour degrades safely.
  * Position independence: the code obtains the runtime image base with the
    `call $+5 / pop ebx / sub ebx, rva` idiom and reaches every IAT slot through
    `[ebx + rva]`. Therefore NO .reloc entries need to be added and ASLR stays
    safe. rel32 CALL/JMP inside the module are inherently relocation-free.
"""
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT_EXE = r"D:\XiuXian\懒人修仙传.patched.exe"

HOOK_VA = 0x476FC7          # call 0x41A120  (the random base-attribute roll)
ORIG_RAND = 0x41A120        # weighted random selector
CAVE_VA = 0x64462A          # 470 zero bytes at the end of .text

# IAT slot VAs (resolved from the import table)
IAT = {
    "CreatePopupMenu": 0x645728,
    "AppendMenuW": 0x645724,
    "GetCursorPos": 0x6457F0,
    "GetForegroundWindow": 0x645600,
    "SetForegroundWindow": 0x6455FC,
    "TrackPopupMenu": 0x645608,
    "DestroyMenu": 0x64556C,
}
MF_STRING = 0x00000000
TPM_LEFTALIGN = 0x0000
TPM_TOPALIGN = 0x0000
TPM_RETURNCMD = 0x0100

ATTR_NAMES = ["\u6839\u9aa8", "\u771f\u6c14", "\u6b66\u672f",
              "\u7075\u529b", "\u7075\u5de7", "\u673a\u7f18"]  # 根骨真气武术灵力灵巧机缘


class Asm:
    """Emits x86-32 machine code at a known VA; supports back-patching."""

    def __init__(self, va):
        self.va = va
        self.b = bytearray()
        self.labels = {}
        self.fixups = []

    # --- low level
    def raw(self, data):
        self.b += data
        self.va += len(data)
        return self

    def here(self):
        return self.va

    def label(self, name):
        self.labels[name] = self.va

    def _modrm_disp(self, reg, base, disp):
        """modrm + disp8/disp32 for [base+disp] (base != esp)."""
        if base & 7 == 4:
            raise ValueError("esp needs SIB")
        reg = reg & 7
        if disp == 0 and (base & 7) != 5:
            return bytes([((reg << 3) | base) & 0xFF])
        if -128 <= disp <= 127:
            return bytes([0x40 | (reg << 3) | (base & 7), disp & 0xFF])
        return bytes([0x80 | (reg << 3) | (base & 7)]) + struct.pack("<i", disp)

    # --- instructions
    def push_r(self, r):
        return self.raw(bytes([0x50 + (r & 7)]))

    def pop_r(self, r):
        return self.raw(bytes([0x58 + (r & 7)]))

    def push_imm(self, v):
        if -128 <= v <= 127:
            return self.raw(bytes([0x6A, v & 0xFF]))
        return self.raw(b"\x68" + struct.pack("<I", v & 0xFFFFFFFF))

    def push_mem(self, base, disp):
        return self.raw(b"\xFF" + self._modrm_disp(6, base, disp))

    def mov_r_imm(self, r, v):
        return self.raw(bytes([0xB8 + (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def mov_r_mem(self, r, base, disp):
        return self.raw(b"\x8B" + self._modrm_disp(r, base, disp))

    def mov_mem_r(self, base, disp, r):
        return self.raw(b"\x89" + self._modrm_disp(r, base, disp))

    def mov_r_r(self, dst, src):
        return self.raw(b"\x8B" + bytes([0xC0 | ((dst & 7) << 3) | (src & 7)]))

    def lea(self, r, base, disp):
        return self.raw(b"\x8D" + self._modrm_disp(r, base, disp))

    def sub_r_imm(self, r, v):
        return self.raw(b"\x81" + bytes([0xE8 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def add_r_imm(self, r, v):
        return self.raw(b"\x81" + bytes([0xC0 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def cmp_r_imm(self, r, v):
        if -128 <= v <= 127:
            return self.raw(b"\x83" + bytes([0xF8 | (r & 7), v & 0xFF]))
        return self.raw(b"\x81" + bytes([0xF8 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def test_r_r(self, a, b):
        return self.raw(b"\x85" + bytes([0xC0 | ((b & 7) << 3) | (a & 7)]))

    def inc_r(self, r):
        return self.raw(bytes([0x40 + (r & 7)]))

    def dec_r(self, r):
        return self.raw(bytes([0x48 + (r & 7)]))

    def call_iat(self, base, slot_va):
        """call dword ptr [base + (slot_va - IMAGE_BASE)]"""
        rva = slot_va - IMAGE_BASE
        return self.raw(b"\xFF" + bytes([0x90 | (2 << 3) | (base & 7)]) + struct.pack("<i", rva))

    def call_rel(self, target_va):
        off = len(self.b) + 1
        self.raw(b"\xE8" + struct.pack("<i", target_va - (self.va + 5)))
        return self

    def jmp_rel(self, target_va):
        return self.raw(b"\xE9" + struct.pack("<i", target_va - (self.va + 5)))

    def jcc_short(self, cc, target_off):
        """cc: 4-bit condition; target_off relative to end of this insn."""
        self.raw(bytes([0x70 | cc, target_off & 0xFF]))
        return self

    def jle_short(self, off):
        return self.jcc_short(0xE, off)

    def jg_short(self, off):
        return self.jcc_short(0xF, off)

    def jmp_short(self, off):
        return self.raw(bytes([0xEB, off & 0xFF]))


def build_code():
    a = Asm(CAVE_VA)

    # ---- prologue: save callee-saved regs (we must honour the MSVC ABI because
    #      the original 0x41A120 preserved them)
    a.push_r(4)                    # push ebp
    a.raw(b"\x8B\xEC")             # mov ebp, esp
    a.push_r(3)                    # push ebx
    a.push_r(6)                    # push esi
    a.push_r(7)                    # push edi
    a.sub_r_imm(4, 0x10)           # sub esp, 0x10    locals

    # ---- obtain runtime image base: call $+5 ; pop ebx ; sub ebx, rva
    a.raw(b"\xE8\x00\x00\x00\x00")  # call $+5
    a.label("geteip")
    a.pop_r(3)                     # pop ebx  -> ebx = VA of this insn
    eip_rva = a.labels["geteip"] - IMAGE_BASE
    a.sub_r_imm(3, eip_rva)        # ebx = runtime image base

    # ---- hmenu = CreatePopupMenu(); bail out if it failed
    a.call_iat(3, IAT["CreatePopupMenu"])
    a.mov_mem_r(4, -4, 0)          # [ebp-4] = hmenu
    a.test_r_r(0, 0)               # test eax, eax
    a.jcc_short(0x4, 0)            # je -> fallback (patched below)
    je_fix = len(a.b) - 1

    # ---- append the six attribute entries
    str_base_rva = None
    for i, nm in enumerate(ATTR_NAMES):
        a.lea(2, 3, 0)             # lea edx, [ebx + 0]  (patched to str rva)
        fix = len(a.b) - 4
        a.push_r(2)                # lpNewItem
        a.push_imm(i + 1)          # uIDNewItem
        a.push_imm(MF_STRING)      # uFlags
        a.push_mem(4, -4)          # hMenu
        a.call_iat(3, IAT["AppendMenuW"])
        a.fixups.append(("str", fix, i))

    # ---- position + owner
    a.lea(0, 4, -0x10)             # lea eax, [ebp-0x10]  (POINT pt)
    a.push_r(0)
    a.call_iat(3, IAT["GetCursorPos"])
    a.call_iat(3, IAT["GetForegroundWindow"])
    a.mov_mem_r(4, -8, 0)          # [ebp-8] = hwnd
    a.push_r(0)
    a.call_iat(3, IAT["SetForegroundWindow"])

    # ---- cmd = TrackPopupMenu(hmenu, TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, NULL)
    a.push_imm(0)                  # prcRect = NULL
    a.push_mem(4, -8)              # hWnd
    a.push_imm(0)                  # nReserved
    a.mov_r_mem(1, 4, -0xC)        # ecx = pt.y
    a.push_r(1)
    a.mov_r_mem(1, 4, -0x10)       # ecx = pt.x
    a.push_r(1)
    a.push_imm(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN)
    a.push_mem(4, -4)              # hMenu
    a.call_iat(3, IAT["TrackPopupMenu"])
    a.mov_r_r(7, 0)                # edi = cmd

    # ---- DestroyMenu(hmenu)
    a.push_mem(4, -4)
    a.call_iat(3, IAT["DestroyMenu"])

    # ---- validate cmd in 1..6
    a.mov_r_r(0, 7)                # eax = cmd
    a.test_r_r(0, 0)
    a.jle_short(0)                 # <=0 -> fallback
    jle_fix = len(a.b) - 1
    a.cmp_r_imm(0, 6)
    a.jg_short(0)                  # >6 -> fallback
    jg_fix = len(a.b) - 1
    a.dec_r(0)                     # return cmd-1 == 0..5

    # ---- success epilogue
    a.label("success")
    a.lea(4, 4, -0xC)              # lea esp, [ebp-0xC]
    a.pop_r(7)
    a.pop_r(6)
    a.pop_r(3)
    a.pop_r(4)                     # pop ebp
    a.raw(b"\xC3")                 # ret   (caller does add esp,8)

    # ---- fallback: tail-jump to the ORIGINAL weighted random with args intact
    a.label("fallback")
    a.lea(4, 4, -0xC)
    a.pop_r(7)
    a.pop_r(6)
    a.pop_r(3)
    a.pop_r(4)
    a.jmp_rel(ORIG_RAND)

    # ---- strings (UTF-16LE, NUL terminated)
    strs = []
    for nm in ATTR_NAMES:
        strs.append((a.here(), nm.encode("utf-16-le") + b"\x00\x00"))
        a.raw(nm.encode("utf-16-le") + b"\x00\x00")

    # ---- back-patch short jumps
    def patch_short(idx, target_va):
        off = target_va - (a.va_of(idx) + 2)
        assert -128 <= off <= 127, "short jump out of range"
        a.b[idx] = off & 0xFF

    # recompute VA of a byte offset
    a.va_of = lambda off: CAVE_VA + off
    for idx, tgt in ((je_fix, a.labels["fallback"]),
                     (jle_fix, a.labels["fallback"]),
                     (jg_fix, a.labels["fallback"])):
        patch_short(idx, tgt)

    # ---- back-patch string displacements
    for _, fix, i in a.fixups:
        a.b[fix:fix + 4] = struct.pack("<i", strs[i][0] - IMAGE_BASE)

    return bytes(a.b), a.labels


def main():
    pe = PE(EXE)
    code, labels = build_code()
    print("injected code size: %d bytes, labels: %s"
          % (len(code), {k: hex(v) for k, v in labels.items()}))

    # verify the cave is free
    cave = pe.raw[pe.va2off(CAVE_VA):pe.va2off(CAVE_VA) + len(code)]
    if any(cave):
        raise SystemExit("cave not empty!")
    trp, tva, trs = pe.text()
    if CAVE_VA + len(code) > IMAGE_BASE + tva + trs:
        # slack beyond VirtualSize but inside the mapped/raw page
        raw_end = trp + trs
        if pe.va2off(CAVE_VA) + len(code) > raw_end:
            raise SystemExit("code does not fit in the cave: need %d" % len(code))

    raw = bytearray(pe.raw)
    # 1) write the injected code into the cave
    o = pe.va2off(CAVE_VA)
    raw[o:o + len(code)] = code
    # 2) redirect the hook
    o = pe.va2off(HOOK_VA)
    assert raw[o] == 0xE8, "hook site is not a call"
    raw[o:o + 5] = b"\xE8" + struct.pack("<i", CAVE_VA - (HOOK_VA + 5))
    open(OUT_EXE, "wb").write(bytes(raw))
    print("wrote %s (%d bytes)" % (OUT_EXE, len(raw)))
    print("hook 0x%X -> 0x%X" % (HOOK_VA, CAVE_VA))


if __name__ == "__main__":
    main()
