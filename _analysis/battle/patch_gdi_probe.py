# -*- coding: utf-8 -*-
"""Build an instrumented build (懒人修仙传.probe.exe) used to locate the GDI
handle leak of the game.

It is the ordinary speed build (patch_battle_speed.py) plus:
  * every `call dword ptr [IAT]` of the GDI create/destroy APIs is redirected to
    a 12-byte thunk that bumps a counter and tail-jumps to the real API;
  * counters live at 0x703EA0..0x703EDC (inside the writable .wash tail),
    thunks live at 0x6FE280.. (free tail of .atrsel, executable);
  * DYNAMIC_BASE is cleared so the image loads at 0x400000 and the thunks may
    use absolute operands (the speed patch itself stays position independent).

Thunk layout (12 bytes):
    FF 05 <counter>     inc dword ptr [counter]
    FF 25 <iat slot>    jmp dword ptr [iat]      ; args/return stack untouched

Counters are read from another process with read_gdi_probe.py.
"""
import hashlib
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
sys.path.insert(0, r"D:\XiuXian\_analysis\battle")
from petool import PE
import patch_battle_speed as P

SRC = P.SRC
OUT = r"D:\XiuXian\懒人修仙传.probe.exe"

THUNK_VA = 0x6FE280
COUNTER_VA = 0x703EA0
THUNK_LEN = 12

APIS = [
    "CreateCompatibleDC",
    "CreateCompatibleBitmap",
    "CreateBitmap",
    "CreateDIBitmap",
    "CreateSolidBrush",
    "CreateHatchBrush",
    "CreatePatternBrush",
    "CreatePen",
    "CreateFontIndirectW",
    "CreateFontW",
    "CreatePalette",
    "LoadBitmapW",
    "DeleteObject",
    "DeleteDC",
    "DestroyIcon",
]


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

    # ---------- the normal speed patch ----------
    off_wait = pe.va2off(P.WAIT_VA)
    assert bytes(raw[off_wait:off_wait + 2]) == P.WAIT_ORIG
    off_hook = pe.va2off(P.HOOK_VA)
    assert bytes(raw[off_hook:off_hook + P.HOOK_LEN]) == P.HOOK_ORIG
    off_log = pe.va2off(P.LOGCHK_VA)
    assert bytes(raw[off_log:off_log + P.LOGCHK_LEN]) == P.LOGCHK_ORIG

    cave1 = P.build_cave1(P.CAVE_VA)
    cave2 = P.build_cave2(P.CAVE_VA + len(cave1))
    off_cave = pe.va2off(P.CAVE_VA)
    need = (P.FLAG_VA + 4) - P.CAVE_VA
    assert not any(raw[off_cave:off_cave + need]), "cave area not free"

    raw[off_hook:off_hook + 5] = b"\xE8" + struct.pack("<i", P.CAVE_VA - (P.HOOK_VA + 5))
    raw[off_hook + 5:off_hook + P.HOOK_LEN] = b"\x90" * (P.HOOK_LEN - 5)
    cave2_va = P.CAVE_VA + len(cave1)
    raw[off_log:off_log + 5] = b"\xE8" + struct.pack("<i", cave2_va - (P.LOGCHK_VA + 5))
    raw[off_log + 5:off_log + P.LOGCHK_LEN] = b"\x90" * (P.LOGCHK_LEN - 5)
    raw[off_wait:off_wait + 2] = P.WAIT_NEW
    raw[off_cave:off_cave + len(cave1) + len(cave2)] = cave1 + cave2

    # .wash writable (flag + counters)
    sh = pe.opt + pe.sizeopt
    for i in range(pe.nsec):
        o = sh + i * 40
        if raw[o:o + 8].rstrip(b"\x00").decode("latin1") == ".wash":
            chars = struct.unpack_from("<I", raw, o + 36)[0]
            struct.pack_into("<I", raw, o + 36, chars | 0x80000000)
            break

    # ---------- instrumentation ----------
    slots = import_slots(pe)
    text_off = pe.sections[0]["rawptr"]
    text_size = pe.sections[0]["rawsize"]
    text_va = 0x400000 + pe.sections[0]["va"]
    text = bytes(raw[text_off:text_off + text_size])

    off_thunk = pe.va2off(THUNK_VA)
    off_count = pe.va2off(COUNTER_VA)
    assert not any(raw[off_thunk:off_thunk + len(APIS) * THUNK_LEN]), "thunk area not free"
    assert not any(raw[off_count:off_count + 4 * len(APIS)]), "counter area not free"

    # validate a candidate by disassembling forward from the enclosing function
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
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
        while pos < len(text) and pos <= rel:
            got = list(md.disasm(text[pos:pos + 15], text_va + pos, count=1))
            if not got:
                return False
            if pos == rel:
                return True
            pos += got[0].size
        return False

    idx = 0
    report = []
    for name in APIS:
        iat = slots.get(name)
        if iat is None:
            report.append((name, -1, 0))
            continue
        sites = []
        pat = b"\xFF\x15" + struct.pack("<I", iat)
        pos = 0
        skipped = 0
        while True:
            j = text.find(pat, pos)
            if j < 0:
                break
            if on_boundary(text_va + j):
                sites.append(text_va + j)
            else:
                skipped += 1
            pos = j + 1
        if skipped:
            print("  (skipped %d non-instruction matches for %s)" % (skipped, name))
        if not sites:
            report.append((name, iat, 0))
            continue

        thunk_va = THUNK_VA + idx * THUNK_LEN
        counter_va = COUNTER_VA + idx * 4
        raw[off_thunk + idx * THUNK_LEN:off_thunk + (idx + 1) * THUNK_LEN] = (
            b"\xFF\x05" + struct.pack("<I", counter_va) +
            b"\xFF\x25" + struct.pack("<I", iat))
        for site in sites:
            o = pe.va2off(site)
            assert bytes(raw[o:o + 6]) == pat
            raw[o:o + 6] = b"\xE8" + struct.pack("<i", thunk_va - (site + 5)) + b"\x90"
        report.append((name, iat, len(sites)))
        idx += 1

    # ---------- no ASLR: absolute operands in the thunks ----------
    dllchar = struct.unpack_from("<H", raw, pe.opt + 70)[0]
    struct.pack_into("<H", raw, pe.opt + 70, dllchar & ~0x40)
    print("DllCharacteristics 0x%04X -> 0x%04X (DYNAMIC_BASE off)"
          % (dllchar, dllchar & ~0x40))

    open(OUT, "wb").write(bytes(raw))
    print("thunks @ 0x%08X (%d used, %d bytes), counters @ 0x%08X"
          % (THUNK_VA, idx, idx * THUNK_LEN, COUNTER_VA))
    for name, iat, n in report:
        if iat is None:
            print("  %-24s not imported" % name)
        else:
            print("  %-24s iat=0x%08X sites=%d" % (name, iat, n))
    print("output:", OUT)
    print("sha256:", hashlib.sha256(bytes(raw)).hexdigest())


if __name__ == "__main__":
    main()
