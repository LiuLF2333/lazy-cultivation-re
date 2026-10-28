# -*- coding: utf-8 -*-
"""Second instrumented build: per-call-site counters for CreateCompatibleDC.

Every `call dword ptr [CreateCompatibleDC]` goes to one thunk that maintains a
256-slot hash table keyed by the caller's return address:

    slot.retaddr  = return address
    slot.count   += 1

so two snapshots taken a few seconds apart give the per-call-site creation rate.
The leaking site is the one whose rate equals the GDI handle growth rate.

Layout
  thunk   0x6FE280  (free tail of .atrsel, executable)
  table   0x704200  256 slots * 8 bytes
  total   0x7041F4
"""
import hashlib
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
sys.path.insert(0, r"D:\XiuXian\_analysis\battle")
from petool import PE
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import patch_battle_speed as P

SRC = P.SRC
OUT = r"D:\XiuXian\懒人修仙传.probe2.exe"

THUNK_VA = 0x6FE280
TABLE_VA = 0x704200
TABLE_N = 256
CNT_VA = 0x7041F4
API = "CreateCompatibleDC"


def import_slots(pe):
    opt = pe.opt
    imp_rva = struct.unpack_from("<I", pe.raw, opt + 104)[0]
    o = pe.va2off(0x400000 + imp_rva)
    slot = {}
    while True:
        ilt, ts, fc, name_rva, iat = struct.unpack_from("<IIIII", pe.raw, o)
        if name_rva == 0:
            break
        t = pe.va2off(0x400000 + (ilt or iat))
        i = 0
        while True:
            v = struct.unpack_from("<I", pe.raw, t)[0]
            if v == 0:
                break
            if not (v & 0x80000000):
                slot[pe.cstr(0x400000 + v + 2)] = 0x400000 + iat + i * 4
            i += 1
            t += 4
        o += 20
    return slot


def main():
    pe = PE(SRC)
    raw = bytearray(pe.raw)

    # --- speed patch ---
    off_wait = pe.va2off(P.WAIT_VA)
    assert bytes(raw[off_wait:off_wait + 2]) == P.WAIT_ORIG
    off_hook = pe.va2off(P.HOOK_VA)
    assert bytes(raw[off_hook:off_hook + P.HOOK_LEN]) == P.HOOK_ORIG
    off_log = pe.va2off(P.LOGCHK_VA)
    assert bytes(raw[off_log:off_log + P.LOGCHK_LEN]) == P.LOGCHK_ORIG

    cave1 = P.build_cave1(P.CAVE_VA)
    cave2 = P.build_cave2(P.CAVE_VA + len(cave1))
    off_cave = pe.va2off(P.CAVE_VA)
    assert not any(raw[off_cave:off_cave + (P.FLAG_VA + 4) - P.CAVE_VA])

    raw[off_hook:off_hook + 5] = b"\xE8" + struct.pack("<i", P.CAVE_VA - (P.HOOK_VA + 5))
    raw[off_hook + 5:off_hook + P.HOOK_LEN] = b"\x90" * (P.HOOK_LEN - 5)
    cave2_va = P.CAVE_VA + len(cave1)
    raw[off_log:off_log + 5] = b"\xE8" + struct.pack("<i", cave2_va - (P.LOGCHK_VA + 5))
    raw[off_log + 5:off_log + P.LOGCHK_LEN] = b"\x90" * (P.LOGCHK_LEN - 5)
    raw[off_wait:off_wait + 2] = P.WAIT_NEW
    raw[off_cave:off_cave + len(cave1) + len(cave2)] = cave1 + cave2

    sh = pe.opt + pe.sizeopt
    for i in range(pe.nsec):
        o = sh + i * 40
        name = raw[o:o + 8].rstrip(b"\x00").decode("latin1")
        if name == ".wash":
            chars = struct.unpack_from("<I", raw, o + 36)[0]
            struct.pack_into("<I", raw, o + 36, chars | 0x80000000)
        if name == ".washd":
            # grow the last (RW) section to 0x1000 bytes so the counter table
            # at 0x704200 is backed by committed, zero filled memory
            struct.pack_into("<I", raw, o + 8, 0x1000)     # VirtualSize

    # --- instrumentation thunk ---
    iat = import_slots(pe)[API]
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    src = """
        push eax
        push edx
        mov  eax, dword ptr [esp + 8]
        mov  edx, eax
        shr  edx, 4
        and  edx, %d
        shl  edx, 3
        add  edx, %d
        cmp  dword ptr [edx], eax
        je   hit
        mov  dword ptr [edx], eax
        mov  dword ptr [edx + 4], 0
    hit:
        inc  dword ptr [edx + 4]
        inc  dword ptr [%d]
        pop  edx
        pop  eax
        jmp  dword ptr [%d]
    """ % (TABLE_N - 1, TABLE_VA, CNT_VA, iat)
    thunk, _ = ks.asm(src, addr=THUNK_VA)
    thunk = bytes(thunk)

    off_thunk = pe.va2off(THUNK_VA)
    assert not any(raw[off_thunk:off_thunk + len(thunk)]), "thunk area not free"

    # --- redirect call sites ---
    text_off = pe.sections[0]["rawptr"]
    text_size = pe.sections[0]["rawsize"]
    text_va = 0x400000 + pe.sections[0]["va"]
    text = bytes(raw[text_off:text_off + text_size])
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def on_boundary(site):
        rel = site - text_va
        j = rel
        while j > 0:
            if text[j] == 0x55 and text[j + 1] == 0x8B and text[j + 2] == 0xEC:
                break
            j -= 1
        if j <= 0:
            return False
        pos = j
        while pos <= rel:
            got = list(md.disasm(text[pos:pos + 15], text_va + pos, count=1))
            if not got:
                return False
            if pos == rel:
                return True
            pos += got[0].size
        return False

    pat = b"\xFF\x15" + struct.pack("<I", iat)
    sites = []
    pos = 0
    while True:
        j = text.find(pat, pos)
        if j < 0:
            break
        if on_boundary(text_va + j):
            sites.append(text_va + j)
        pos = j + 1

    for site in sites:
        o = pe.va2off(site)
        assert bytes(raw[o:o + 6]) == pat
        raw[o:o + 6] = b"\xE8" + struct.pack("<i", THUNK_VA - (site + 5)) + b"\x90"
    raw[off_thunk:off_thunk + len(thunk)] = thunk

    # --- no ASLR so the thunk may use absolute addresses ---
    dllchar = struct.unpack_from("<H", raw, pe.opt + 70)[0]
    struct.pack_into("<H", raw, pe.opt + 70, dllchar & ~0x40)

    open(OUT, "wb").write(bytes(raw))
    print("%s: %d call sites, thunk %d bytes" % (API, len(sites), len(thunk)))
    print("table 0x%08X (%d slots x 8)" % (TABLE_VA, TABLE_N))
    print("output:", OUT)
    print("sha256:", hashlib.sha256(bytes(raw)).hexdigest())


if __name__ == "__main__":
    main()
