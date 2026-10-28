# -*- coding: utf-8 -*-
"""Patch 懒人修仙传.exe: type1=110 random base-attribute pills now pop a
Win32 popup chooser so the player picks the attribute.

Hook: VA 0x476FC7  (`call 0x41A120` — the weighted random attribute roll)
Cave: VA 0x64462A  (470 zero bytes at the tail of .text, mapped & executable)

Frame layout:
    push ebp ; mov ebp,esp
    push ebx ; push esi ; push edi        -> [ebp-4], [ebp-8], [ebp-0xC]
    sub  esp,0x10                         -> locals
    [ebp-0x10] hmenu
    [ebp-0x14] hwnd
    [ebp-0x18] POINT.x
    [ebp-0x1C] POINT.y

Position independence (ASLR is enabled, DYNAMIC_BASE set):
    call $+5 ; pop ebx ; sub ebx, <rva of pop>   => ebx = runtime image base
    every IAT slot is reached as [ebx + rva_slot]; every intra-module transfer
    is rel32. No absolute address is ever materialised, so NO .reloc entry is
    required and the loader leaves the code correct after relocation.
"""
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT_EXE = r"D:\XiuXian\懒人修仙传.patched.exe"

HOOK_VA = 0x476FC7
ORIG_RAND = 0x41A120
CAVE_VA = 0x64462A

IAT = {
    "CreatePopupMenu": 0x645728,
    "AppendMenuW": 0x645724,
    "GetCursorPos": 0x6457F0,
    "GetForegroundWindow": 0x645600,
    "SetForegroundWindow": 0x6455FC,
    "TrackPopupMenu": 0x645608,
    "DestroyMenu": 0x64556C,
    "GetActiveWindow": 0x6456D8,
}
MF_STRING = 0x00000000
TPM_RETURNCMD = 0x0100

ATTR_NAMES = ["\u6839\u9aa8", "\u771f\u6c14", "\u6b66\u672f",
              "\u7075\u529b", "\u7075\u5de7", "\u673a\u7f18"]


class Asm:
    def __init__(self, va):
        self.va = va
        self.b = bytearray()
        self.labels = {}
        self.short_fix = []   # (disp_offset, label)
        self.str_fix = []     # (disp_offset, index)

    def raw(self, d):
        self.b += d
        self.va += len(d)
        return self

    def label(self, n):
        self.labels[n] = self.va

    def va_at(self, off):
        return CAVE_VA + off

    # ---------- operand encoders (always allow disp32 where needed) ----------
    @staticmethod
    def _mrm(reg, base, disp, force32=False):
        reg &= 7
        base &= 7
        assert base != 4, "esp base needs SIB"
        if not force32:
            if disp == 0 and base != 5:
                return bytes([((reg << 3) | base) & 0xFF])
            if -128 <= disp <= 127:
                return bytes([0x40 | (reg << 3) | base, disp & 0xFF])
        return bytes([0x80 | (reg << 3) | base]) + struct.pack("<i", disp)

    # ---------- instructions ----------
    def push_r(self, r):   return self.raw(bytes([0x50 + (r & 7)]))
    def pop_r(self, r):    return self.raw(bytes([0x58 + (r & 7)]))

    def push_imm(self, v):
        if -128 <= v <= 127:
            return self.raw(bytes([0x6A, v & 0xFF]))
        return self.raw(b"\x68" + struct.pack("<I", v & 0xFFFFFFFF))

    def push_mem(self, base, disp):
        return self.raw(b"\xFF" + self._mrm(6, base, disp))

    def mov_r_mem(self, r, base, disp):
        return self.raw(b"\x8B" + self._mrm(r, base, disp))

    def mov_mem_r(self, base, disp, r):
        return self.raw(b"\x89" + self._mrm(r, base, disp))

    def mov_r_r(self, dst, src):
        return self.raw(b"\x8B" + bytes([0xC0 | ((dst & 7) << 3) | (src & 7)]))

    def lea(self, r, base, disp, force32=False):
        return self.raw(b"\x8D" + self._mrm(r, base, disp, force32))

    def sub_r_imm(self, r, v):
        return self.raw(b"\x81" + bytes([0xE8 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def cmp_r_imm(self, r, v):
        if -128 <= v <= 127:
            return self.raw(b"\x83" + bytes([0xF8 | (r & 7), v & 0xFF]))
        return self.raw(b"\x81" + bytes([0xF8 | (r & 7)]) + struct.pack("<I", v & 0xFFFFFFFF))

    def test_r_r(self, a, b):
        return self.raw(b"\x85" + bytes([0xC0 | ((b & 7) << 3) | (a & 7)]))

    def dec_r(self, r):    return self.raw(bytes([0x48 + (r & 7)]))

    def call_iat(self, base, slot_va):
        rva = (slot_va - IMAGE_BASE) & 0xFFFFFFFF
        return self.raw(b"\xFF" + bytes([0x90 | (2 << 3) | (base & 7)]) + struct.pack("<I", rva))

    def call_rel(self, target):
        return self.raw(b"\xE8" + struct.pack("<i", target - (self.va + 5)))

    def jmp_rel(self, target):
        return self.raw(b"\xE9" + struct.pack("<i", target - (self.va + 5)))

    def jcc(self, cc, label):
        # near form: 0F 8x rel32 (always in range)
        self.raw(bytes([0x0F, 0x80 | cc]) + b"\x00\x00\x00\x00")
        self.short_fix.append((len(self.b) - 4, label, "jcc"))
        return self

    def jmp(self, label):
        self.raw(b"\xE9\x00\x00\x00\x00")
        self.short_fix.append((len(self.b) - 4, label, "jmp"))
        return self


def build():
    a = Asm(CAVE_VA)
    # ebp = 5, ebx = 3, esi = 6, edi = 7
    a.push_r(5); a.raw(b"\x8B\xEC")          # push ebp ; mov ebp,esp
    a.push_r(3); a.push_r(6); a.push_r(7)    # push ebx,esi,edi
    a.sub_r_imm(4, 0x1C)                     # sub esp,0x1C  (esp = ebp-0x28)
    # frame: [ebp-0x04] ebx | [-0x08] esi | [-0x0C] edi
    #        [-0x10] hmenu | [-0x14] hwnd
    #        POINT at [-0x20]: pt.x=[-0x20], pt.y=[-0x1C]

    # ebx = runtime image base
    a.raw(b"\xE8\x00\x00\x00\x00")           # call $+5
    a.label("geteip")
    a.pop_r(3)                               # pop ebx
    a.sub_r_imm(3, a.labels["geteip"] - IMAGE_BASE)

    # hmenu = CreatePopupMenu()
    a.call_iat(3, IAT["CreatePopupMenu"])
    a.mov_mem_r(5, -0x10, 0)                 # [ebp-0x10] = hmenu
    a.test_r_r(0, 0)
    a.jcc(0x4, "fallback")                   # je fallback

    # six entries
    for i, nm in enumerate(ATTR_NAMES):
        a.lea(2, 3, 0, force32=True)         # lea edx,[ebx+<rva>] (patched)
        a.str_fix.append((len(a.b) - 4, i))
        a.push_r(2)                          # lpNewItem
        a.push_imm(i + 1)                    # uIDNewItem 1..6
        a.push_imm(MF_STRING)                # uFlags
        a.push_mem(5, -0x10)                 # hMenu
        a.call_iat(3, IAT["AppendMenuW"])

    # foreground + cursor
    a.lea(0, 5, -0x20)                       # lea eax,[ebp-0x20] (POINT: x,y)
    a.push_r(0)
    a.call_iat(3, IAT["GetCursorPos"])
    a.call_iat(3, IAT["GetForegroundWindow"])
    a.mov_mem_r(5, -0x14, 0)                 # [ebp-0x14] = hwnd
    a.test_r_r(0, 0)
    a.jcc(0x5, "have_hwnd")                  # jne have_hwnd
    a.call_iat(3, IAT["GetActiveWindow"])    # fall back to the active window
    a.mov_mem_r(5, -0x14, 0)
    a.label("have_hwnd")
    a.push_mem(5, -0x14)
    a.call_iat(3, IAT["SetForegroundWindow"])

    # cmd = TrackPopupMenu(hmenu, TPM_RETURNCMD, x, y, 0, hwnd, NULL)
    a.push_imm(0)                            # prcRect
    a.push_mem(5, -0x14)                     # hWnd
    a.push_imm(0)                            # nReserved
    a.mov_r_mem(1, 5, -0x1C)                 # ecx = pt.y
    a.push_r(1)
    a.mov_r_mem(1, 5, -0x20)                 # ecx = pt.x
    a.push_r(1)
    a.push_imm(TPM_RETURNCMD)
    a.push_mem(5, -0x10)                     # hMenu
    a.call_iat(3, IAT["TrackPopupMenu"])
    a.mov_r_r(7, 0)                          # edi = cmd

    # DestroyMenu
    a.push_mem(5, -0x10)
    a.call_iat(3, IAT["DestroyMenu"])

    # validate 1..6
    a.mov_r_r(0, 7)
    a.test_r_r(0, 0)
    a.jcc(0xE, "fallback")                   # jle fallback
    a.cmp_r_imm(0, 6)
    a.jcc(0xF, "fallback")                   # jg  fallback
    a.dec_r(0)                               # 0..5

    a.label("epilogue")
    a.lea(4, 5, -0xC)                        # lea esp,[ebp-0xC]
    a.pop_r(7); a.pop_r(6); a.pop_r(3); a.pop_r(5)   # pop edi,esi,ebx,ebp
    a.raw(b"\xC3")                           # ret

    a.label("fallback")
    a.lea(4, 5, -0xC)
    a.pop_r(7); a.pop_r(6); a.pop_r(3); a.pop_r(5)
    a.jmp_rel(ORIG_RAND)                     # tail-call original weighted RNG

    strs = []
    for nm in ATTR_NAMES:
        blob = nm.encode("utf-16-le") + b"\x00\x00"
        strs.append(a.va)
        a.raw(blob)

    for disp_off, lbl, kind in a.short_fix:
        target = a.labels[lbl]
        if kind == "jcc":
            off = target - (a.va_at(disp_off) + 4)
        else:
            off = target - (a.va_at(disp_off) + 4)
        assert -(1 << 31) <= off < (1 << 31), "rel32 out of range"
        a.b[disp_off:disp_off + 4] = struct.pack("<i", off)
    for disp_off, i in a.str_fix:
        a.b[disp_off:disp_off + 4] = struct.pack("<i", strs[i] - IMAGE_BASE)

    return bytes(a.b)


def main():
    code = build()
    pe = PE(EXE)
    if len(code) > 470:
        raise SystemExit("code %d bytes > 470-byte cave" % len(code))
    cave_off = pe.va2off(CAVE_VA)
    assert not any(pe.raw[cave_off:cave_off + len(code)]), "cave not empty"
    hook_off = pe.va2off(HOOK_VA)
    assert pe.raw[hook_off] == 0xE8, "hook site is not E8"

    # report
    print("code %d bytes, strings at %s" % (len(code), hex(CAVE_VA + len(code) - 96)))
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    n = 0
    for ins in md.disasm(code, CAVE_VA):
        if n < 14 or "pop ebp" in ins.mnemonic:
            print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        n += 1
    print("   ... %d instructions total" % n)

    raw = bytearray(pe.raw)
    raw[cave_off:cave_off + len(code)] = code
    raw[hook_off:hook_off + 5] = b"\xE8" + struct.pack("<i", CAVE_VA - (HOOK_VA + 5))
    open(OUT_EXE, "wb").write(bytes(raw))
    print("wrote %s" % OUT_EXE)
    print("hook 0x%X -> cave 0x%X" % (HOOK_VA, CAVE_VA))


if __name__ == "__main__":
    main()
