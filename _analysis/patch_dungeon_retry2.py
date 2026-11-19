"""Reliable dungeon auto-retry (v2) for 懒人修仙传 1.1.1.11.

Replaces the old AutoDungeon hook (which only forced [rt+0x5A0]=4/[rt+0x5B8]=5
at the defeat exit) with a mode-independent, gate-independent implementation.

Why the old one stalled
-----------------------
The OnTimer (WM_TIMER 0x3E9) dungeon block is:

    0x4C5F3C  movzx edx,[ecx+0x599] / test / je 0x4C5F6A   ; whole block
    0x4C5F73  call 0x490A30 / je 0x4C5FF0                  ; timer+dispatch
    0x4C5F88  cmp  [rt+0x5B8],0 / jle skip
              dec  [rt+0x5B8] / jne skip
              call 0x490DA0                                ; state machine
              push 0 / push 0x64 / push 0x3EE / call 0x452660

So the pending state only advances when byte [rt+0x599]!=0 *and* the dungeon's
mode ([rt+0x4C], copied from the dungeon definition field +8) is 1.  For any
other dungeon type the timer never counts down, 0x490DA0 never runs and WM_TIMER
0x3EE is never re-armed -- i.e. the retry silently does nothing and the run sits
on the failure screen until the player clicks "enter" by hand.

The built-in retry (0x4C6335, WM_TIMER 0x3EE) is equally conditional: it needs
[rt+4]==0, waits [game+0x24FC] >= 100 ticks (10 s) and then relies on 0x490C20,
which bails out to state 5/2 when byte [rt+0x596]==0, when the controller says
[ctrl+0x38] is 1 or 2, or when no attempts are left ([ctrl+0x14]).

What v2 does
------------
Hook A  0x48FE4C  (single common exit of *every* dungeon result==2 defeat path)
        sets PEND=1.

Hook B  0x4C5D66  (runs unconditionally on the 100 ms WM_TIMER 0x3E9 tick)
        Part 1  services state 3/4 ourselves when the vanilla gate is closed,
                by decrementing [rt+0x5B8] and calling 0x490DA0 -- so the
                controller always reaches the idle state a manual click needs.
        Part 2  once the controller is idle and a dungeon target is still set,
                calls 0x490E40 == "push [rt+0x56c]; ecx=rt; call 0x48C0F0",
                which is exactly what the enter-dungeon UI click does
                (0x4BD7F6).  Verified with a 3 s window; up to 3 attempts.

Everything is position independent (rel32 jumps/calls plus a call/pop base
register), so it survives ASLR.  The code and its state live in a brand new
`.dgret` section (code|execute|read|write) appended to the image.

Usage:  python patch_dungeon_retry2.py [src.exe] [out.exe]
"""

import glob
import hashlib
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DEFAULT_SRC = r"D:\XiuXian\懒人修仙传.wild.exe"
DEFAULT_OUT = r"D:\XiuXian\懒人修仙传.wild2.exe"
ORIGINAL_SHA256 = "A84DE8DC435C7765E38A62C89C6ABFEEFF4A1E80D8D04C707407AC52C20556D5"

# --- hook sites -------------------------------------------------------------
HOOK_FAIL_VA = 0x48FE4C     # jmp 0x48FF0B  (result==2 defeat, all exits)
HOOK_FAIL_LEN = 5
HOOK_FAIL_RESUME = 0x48FF0B

HOOK_TICK_VA = 0x4C5D66     # mov ecx,[ebp-4] ; mov edx,[ecx+0x24F0]
HOOK_TICK_LEN = 9
HOOK_TICK_ORIG = bytes.fromhex("8b4dfc8b91f0240000")
HOOK_TICK_RESUME = 0x4C5D6F

# --- game routines used -----------------------------------------------------
STATE_DISPATCH_VA = 0x490DA0   # __thiscall(ecx=rt), switches on [rt+0x5A0]
DUNGEON_ENTER_VA = 0x490E40    # __thiscall(ecx=rt): push [rt+0x56c]; call 0x48C0F0
MESSAGE_VA = 0x416F90

# --- layout of the new section ---------------------------------------------
SECTION_NAME = b".dgret"
SECTION_VA = 0x705000          # RVA 0x305000, right after .washd
CAVE_A_VA = SECTION_VA          # defeat marker
CAVE_B_VA = SECTION_VA + 0x80   # tick watchdog
DATA_VA = SECTION_VA + 0xF00    # four dwords of state
PEND_OFF = DATA_VA + 0x00
COOL_OFF = DATA_VA + 0x04
FIRED_OFF = DATA_VA + 0x08
TRIES_OFF = DATA_VA + 0x0C

COOLDOWN_TICKS = 30             # 3 s at 100 ms/tick
MAX_TRIES = 3
IDLE_STATES = "0, 2, 5"         # states a hand click works from


def asm(src, base):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    enc, count = ks.asm(src, base)
    if enc is None:
        raise RuntimeError("assembly failed at 0x%08X" % base)
    return bytes(enc)


def build_fail_marker():
    """Hook A: latch the defeat so the watchdog restarts the next run."""
    src = """
        pushad
        mov  esi, dword ptr [ebp - 4]
        test esi, esi
        jz   dg_fail_done
        cmp  dword ptr [esi + 0x56C], 0
        je   dg_fail_done

        call dg_fail_eip
    dg_fail_eip:
        pop  edi
        sub  edi, dg_fail_eip - 0x%08X

        mov  dword ptr [edi + 0x%08X], 1
        mov  dword ptr [edi + 0x%08X], 0
        mov  dword ptr [edi + 0x%08X], 0
        mov  dword ptr [edi + 0x%08X], 0
    dg_fail_done:
        popad
        jmp  0x%08X
    """ % (IMAGE_BASE, PEND_OFF - IMAGE_BASE, COOL_OFF - IMAGE_BASE,
           FIRED_OFF - IMAGE_BASE, TRIES_OFF - IMAGE_BASE, HOOK_FAIL_RESUME)
    return asm(src, CAVE_A_VA)


def build_tick_watchdog():
    """Hook B: mode-independent state servicing + direct re-entry when idle."""
    src = """
        pushad
        mov  eax, dword ptr [ebp - 4]
        test eax, eax
        jz   dg_done
        mov  esi, dword ptr [eax + 0x24F4]
        test esi, esi
        jz   dg_done

        call dg_tick_eip
    dg_tick_eip:
        pop  edi
        sub  edi, dg_tick_eip - 0x%08X

        ; ---- Part 1: service the pending state when vanilla cannot ----
        mov  edx, dword ptr [esi + 0x5A0]
        cmp  edx, 3
        je   dg_p1
        cmp  edx, 4
        jne  dg_p2
    dg_p1:
        cmp  dword ptr [esi + 0x4C], 1
        jne  dg_p1_go
        cmp  byte ptr [esi + 0x599], 0
        jne  dg_p2
    dg_p1_go:
        mov  ecx, dword ptr [esi + 0x5B8]
        test ecx, ecx
        jz   dg_p1_fire
        sub  ecx, 1
        mov  dword ptr [esi + 0x5B8], ecx
        jnz  dg_p2
    dg_p1_fire:
        mov  dword ptr [edi + 0x%08X], 0
        mov  ecx, esi
        call 0x%08X
        mov  eax, dword ptr [ebp - 4]
        mov  dword ptr [eax + 0x24FC], 0
        jmp  dg_done

        ; ---- Part 2: restart once the controller is idle ----
    dg_p2:
        mov  ecx, dword ptr [edi + 0x%08X]
        test ecx, ecx
        jz   dg_p2_fire
        sub  ecx, 1
        mov  dword ptr [edi + 0x%08X], ecx
        jnz  dg_done
        cmp  dword ptr [edi + 0x%08X], 0
        je   dg_done
        mov  dword ptr [edi + 0x%08X], 0

        cmp  dword ptr [esi + 4], 0
        jne  dg_p2_ok
        mov  edx, dword ptr [esi + 0x5A0]
        cmp  edx, 1
        je   dg_p2_ok
        cmp  edx, 3
        je   dg_p2_ok
        cmp  edx, 4
        je   dg_p2_ok
        ; the restart never took: re-arm if the budget allows
        mov  eax, dword ptr [edi + 0x%08X]
        cmp  eax, %d
        jae  dg_p2_giveup
        mov  dword ptr [edi + 0x%08X], 1
        jmp  dg_done
    dg_p2_giveup:
        mov  dword ptr [edi + 0x%08X], 0
        jmp  dg_done
    dg_p2_ok:
        mov  dword ptr [edi + 0x%08X], 0
        jmp  dg_done

    dg_p2_fire:
        cmp  dword ptr [edi + 0x%08X], 0
        je   dg_done
        cmp  dword ptr [esi + 0x56C], 0
        je   dg_p2_clear
        cmp  dword ptr [esi + 4], 0
        jne  dg_done
        mov  edx, dword ptr [esi + 0x5A0]
        test edx, edx
        jz   dg_go
        cmp  edx, 2
        je   dg_go
        cmp  edx, 5
        jne  dg_done
    dg_go:
        mov  dword ptr [edi + 0x%08X], 0
        mov  dword ptr [edi + 0x%08X], %d
        mov  dword ptr [edi + 0x%08X], 1
        mov  eax, dword ptr [edi + 0x%08X]
        add  eax, 1
        mov  dword ptr [edi + 0x%08X], eax
        mov  ecx, esi
        call 0x%08X
        jmp  dg_done
    dg_p2_clear:
        mov  dword ptr [edi + 0x%08X], 0

    dg_done:
        popad
        mov  ecx, dword ptr [ebp - 4]
        mov  edx, dword ptr [ecx + 0x24F0]
        jmp  0x%08X
    """ % (IMAGE_BASE,
           PEND_OFF - IMAGE_BASE,
           STATE_DISPATCH_VA,
           COOL_OFF - IMAGE_BASE,
           COOL_OFF - IMAGE_BASE,
           FIRED_OFF - IMAGE_BASE,
           FIRED_OFF - IMAGE_BASE,
           TRIES_OFF - IMAGE_BASE,
           MAX_TRIES,
           PEND_OFF - IMAGE_BASE,
           TRIES_OFF - IMAGE_BASE,
           TRIES_OFF - IMAGE_BASE,
           PEND_OFF - IMAGE_BASE,
           PEND_OFF - IMAGE_BASE,
           COOL_OFF - IMAGE_BASE,
           COOLDOWN_TICKS,
           FIRED_OFF - IMAGE_BASE,
           TRIES_OFF - IMAGE_BASE,
           TRIES_OFF - IMAGE_BASE,
           DUNGEON_ENTER_VA,
           PEND_OFF - IMAGE_BASE,
           HOOK_TICK_RESUME)
    return asm(src, CAVE_B_VA)


def sha256(data):
    return hashlib.sha256(data).hexdigest().upper()


def find_pristine():
    for path in sorted(glob.glob(r"D:\XiuXian\*.exe.bak.*")):
        with open(path, "rb") as fp:
            if sha256(fp.read()).startswith(ORIGINAL_SHA256[:8]):
                return path
    raise SystemExit("no pristine backup found")


def check(pe, va, expected, what):
    got = pe.bytes_at(va, len(expected))
    if got != expected:
        raise SystemExit("%s @0x%08X: expected %s, found %s"
                         % (what, va, expected.hex(" "), got.hex(" ")))


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    out = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT

    pe = PE(src)
    raw = bytearray(pe.raw)
    print("source %s" % src)
    print("sha256 %s" % sha256(raw))

    fail_orig = pe.bytes_at(HOOK_FAIL_VA, HOOK_FAIL_LEN)
    if fail_orig[0] != 0xE9:
        raise SystemExit("0x%08X is not a jmp anymore: %s"
                         % (HOOK_FAIL_VA, fail_orig.hex(" ")))
    print("defeat hook site 0x%08X: %s -> 0x%08X"
          % (HOOK_FAIL_VA, fail_orig.hex(" "),
             HOOK_FAIL_VA + 5 + struct.unpack_from("<i", fail_orig, 1)[0]))
    check(pe, HOOK_TICK_VA, HOOK_TICK_ORIG, "tick hook site")

    # ---- section header room -------------------------------------------------
    opt = pe.opt
    nsec = pe.nsec
    sec_align, file_align = struct.unpack_from("<II", raw, opt + 32)
    hdr_room = struct.unpack_from("<I", raw, opt + 60)[0]
    new_hdr = opt + pe.sizeopt + nsec * 40
    if new_hdr + 40 > pe.sections[0]["rawptr"]:
        raise SystemExit("no room for another section header")
    print("sections=%d sec_align=0x%X file_align=0x%X size_of_headers=0x%X"
          % (nsec, sec_align, file_align, hdr_room))

    last = pe.sections[-1]
    new_rva = (last["va"] + last["vsize"] + sec_align - 1) & ~(sec_align - 1)
    if new_rva != SECTION_VA - IMAGE_BASE:
        raise SystemExit("unexpected next RVA 0x%08X" % new_rva)
    new_rawptr = (len(raw) + file_align - 1) & ~(file_align - 1)
    vsize = 0x1000

    # ---- build the payload ---------------------------------------------------
    fail_marker = build_fail_marker()
    tick = build_tick_watchdog()
    if CAVE_A_VA + len(fail_marker) > CAVE_B_VA:
        raise SystemExit("hook A code overflows into hook B")
    if CAVE_B_VA + len(tick) > DATA_VA:
        raise SystemExit("hook B code overflows into the data block")
    print("hook A: %d bytes, hook B: %d bytes (limit %d)"
          % (len(fail_marker), len(tick), DATA_VA - CAVE_B_VA))

    payload = bytearray(vsize)
    payload[CAVE_A_VA - SECTION_VA:][:len(fail_marker)] = fail_marker
    payload[CAVE_B_VA - SECTION_VA:][:len(tick)] = tick

    # ---- append the section --------------------------------------------------
    raw += b"\x00" * (new_rawptr - len(raw))
    raw += payload

    hdr = bytearray(40)
    hdr[0:len(SECTION_NAME)] = SECTION_NAME
    struct.pack_into("<I", hdr, 8, vsize)          # VirtualSize
    struct.pack_into("<I", hdr, 12, new_rva)       # VirtualAddress
    struct.pack_into("<I", hdr, 16, vsize)         # SizeOfRawData
    struct.pack_into("<I", hdr, 20, new_rawptr)    # PointerToRawData
    struct.pack_into("<I", hdr, 36, 0xE0000020)    # code|execute|read|write
    raw[new_hdr:new_hdr + 40] = hdr
    struct.pack_into("<H", raw, fh + 2, nsec + 1)
    struct.pack_into("<I", raw, opt + 56, new_rva + vsize)   # SizeOfImage

    # ---- install the hooks ---------------------------------------------------
    def put(va, data):
        off = pe.va2off(va)
        raw[off:off + len(data)] = data

    put(HOOK_FAIL_VA, b"\xE9" + struct.pack("<i", CAVE_A_VA - (HOOK_FAIL_VA + 5)))
    put(HOOK_TICK_VA, b"\xE9" + struct.pack("<i", CAVE_B_VA - (HOOK_TICK_VA + 5))
        + b"\x90" * (HOOK_TICK_LEN - 5))

    with open(out, "wb") as fp:
        fp.write(raw)
    print("wrote %s" % out)
    print("sha256 %s" % sha256(raw))

    # ---- verify --------------------------------------------------------------
    out_pe = PE(out)
    new_sec = [s for s in out_pe.sections if s["name"] == ".dgret"]
    if len(new_sec) != 1:
        raise SystemExit("new section missing")
    sec = new_sec[0]
    print("section .dgret VA=0x%08X vsize=0x%X rawptr=0x%X rawsize=0x%X chars=0x%08X"
          % (sec["va"], sec["vsize"], sec["rawptr"], sec["rawsize"], sec["chars"]))
    if out_pe.bytes_at(CAVE_A_VA, len(fail_marker)) != fail_marker:
        raise SystemExit("hook A payload mismatch")
    if out_pe.bytes_at(CAVE_B_VA, len(tick)) != tick:
        raise SystemExit("hook B payload mismatch")
    if out_pe.bytes_at(DATA_VA, 0x10) != b"\x00" * 0x10:
        raise SystemExit("state block not zeroed")
    size_image = struct.unpack_from("<I", out_pe.raw, out_pe.opt + 56)[0]
    print("SizeOfImage=0x%08X NumberOfSections=%d"
          % (size_image, struct.unpack_from("<H", out_pe.raw, fh + 2)[0]))
    if HOOK_FAIL_VA + 5 + struct.unpack_from("<i", out_pe.bytes_at(HOOK_FAIL_VA, 5), 1)[0] != CAVE_A_VA:
        raise SystemExit("hook A jump target mismatch")
    if HOOK_TICK_VA + 5 + struct.unpack_from("<i", out_pe.bytes_at(HOOK_TICK_VA, 5), 1)[0] != CAVE_B_VA:
        raise SystemExit("hook B jump target mismatch")

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for label, va, code in (("hook A (defeat marker)", CAVE_A_VA, fail_marker),
                            ("hook B (tick watchdog)", CAVE_B_VA, tick)):
        print("\n--- %s @0x%08X ---" % (label, va))
        for ins in md.disasm(code, va):
            print("0x%08X  %-22s %s %s"
                  % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))


if __name__ == "__main__":
    main()
