"""Reliable dungeon auto-retry (v3) for 懒人修仙传 1.1.1.11.

Why the old AutoDungeon patch stalled
-------------------------------------
The old hook only wrote  [rt+0x5A0] = 4 / [rt+0x5B8] = 5  on the defeat exit
and relied on the vanilla controller to finish the job.  That controller is
gated twice in the WM_TIMER 0x3E9 handler:

    0x4C5F73  call 0x490A30            ; [rt+0x4C] == 1 ?  (dungeon mode)
    0x4C5F7D  je   0x4C5FF0            ; mode != 1  ->  skip timer + dispatch
    0x4C5F88  cmp  dword [rt+0x5B8], 0 / jle skip
              dec  dword [rt+0x5B8] / jne skip
              call 0x490DA0            ; state machine
              push 0 / push 0x64 / push 0x3EE / call 0x452660   ; re-arm

So for every dungeon whose type field is not 1 the countdown never runs,
0x490DA0 never runs, WM_TIMER 0x3EE is never re-armed and the run sits on the
failure screen until the player clicks "enter" by hand.  The built-in retry
(0x4C6335) is just as conditional ([rt+4]==0, [game+0x24FC] >= 100,
byte [rt+0x596] != 0, controller [ctrl+0x38] not 1/2, attempts left).

What v3 does  (no dependency on any of those gates)
---------------------------------------------------
Hook A  0x48FE4C   the single common exit of *every* result==2 defeat path
                   (0x48FDAB/0x48FDB8/0x48FDCB/0x48FDFE/0x48FE47 all land here;
                   results 1 and 3 leave through other jumps).  Sets PEND=1 and
                   clears COOL.

Hook B  0x4C5D66   runs unconditionally on the 100 ms WM_TIMER 0x3E9 tick.
                   PEND set and COOL expired  ->  put the controller in the idle
                   state, drop the stale battle object, then call 0x490E40,
                   which is byte-for-byte what the "enter dungeon" button does
                   (push [rt+0x56C]; ecx = rt; call 0x48C0F0).

The tick that restarts a run deliberately skips the speed-up burst for that
single tick, so the freshly built run is never driven by the battle machine
inside the same timer callback.

The hook is chain-safe: the resume sequence is chosen from the bytes that are
actually present at the hook site, so this patch can be applied on top of the
plain game (two original instructions) *or* on top of the speed-up build
(re-enters the burst cave with the return address it expects).

Everything is position independent (rel32 + call/pop base register) because the
image is /DYNAMICBASE.  Code and state live in the tail of `.washd`, which is
grown from one page to two pages (0x704000..0x705000); `.washd` is already
IMAGE_SCN_CNT_INITIALIZED_DATA|MEM_READ|MEM_WRITE and is the last section in
the file, so the growth needs no raw-pointer relocation and no extra section
header (the header table is full).

Usage:  python patch_dungeon_retry3.py [src.exe] [out.exe]
"""

import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DEFAULT_SRC = r"D:\XiuXian\懒人修仙传.speed3.exe"
DEFAULT_OUT = r"D:\XiuXian\懒人修仙传.final.exe"

# --- hook sites -------------------------------------------------------------
HOOK_FAIL_VA = 0x48FE4C          # jmp 0x48FF0B on the defeat exit
HOOK_FAIL_LEN = 5
HOOK_FAIL_RESUME = 0x48FF0B      # common tail: log + [rt+0x40]=0 + ret

HOOK_TICK_VA = 0x4C5D66          # moves [game+0x24F0] into edx, every 100 ms
HOOK_TICK_LEN = 9
HOOK_TICK_ORIG = bytes.fromhex("8b4dfc8b91f0240000")
HOOK_TICK_RET = 0x4C5D6B         # return address the burst cave expects
HOOK_TICK_RESUME = 0x4C5D6F

# the burst cave is entered with `call`, but ends with a plain jmp, so every
# tick leaks four bytes of stack; turn that tail into a `ret` back to the two
# patched sites' return slot (0x4C5D6B, four nops) -- correct for the original
# call and for the chained entry emitted below.
SPEED_TAIL_VA = 0x703E66
SPEED_TAIL_ORIG = bytes.fromhex("e9041fdcff")
SPEED_TAIL_NEW = bytes.fromhex("c390909090")

# --- game routines ----------------------------------------------------------
DUNGEON_ENTER_VA = 0x490E40      # __thiscall(ecx=rt): push [rt+0x56C]; call 0x48C0F0

# --- layout (tail of .washd) ------------------------------------------------
SECTION_NAME = ".washd"
SECTION_VA = 0x704000            # RVA 0x304000
SECTION_VSIZE = 0x1000           # one page -> two pages
SECTION_RAWSIZE = 0x1000
SECTION_CHARS = 0xE0000020       # CODE | EXECUTE | READ | WRITE
CAVE_FAIL_VA = 0x704200
CAVE_TICK_VA = 0x704280
DATA_VA = 0x704F00
PEND_RVA = DATA_VA - IMAGE_BASE + 0x00      # 0x304F00
COOL_RVA = DATA_VA - IMAGE_BASE + 0x04      # 0x304F04

COOLDOWN_TICKS = 15              # 1.5 s at 100 ms/tick


def asm(src, base):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    enc, count = ks.asm(src, base)
    if enc is None:
        raise RuntimeError("assembly failed at 0x%08X" % base)
    return bytes(enc)


def washd_reader(pe):
    """Read .washd by raw offset; works past VirtualSize, unlike bytes_at()."""
    s = [x for x in pe.sections if x["name"] == SECTION_NAME][0]
    base_va = IMAGE_BASE + s["va"]

    def read(va, n):
        off = s["rawptr"] + (va - base_va)
        return bytes(pe.raw[off:off + n])

    return read


def _resume(src_bytes, fail_chain):
    """Emitter for the two tail variants, used by both hooks."""
    raise NotImplementedError


def build_fail_marker(chain_va):
    """Hook A: latch a defeat; the watchdog restarts the next run."""
    src = """
        pushad
        mov  esi, dword ptr [ebp - 4]
        test esi, esi
        jz   dfail_done
        cmp  dword ptr [esi + 0x56C], 0
        je   dfail_done

        call dfail_eip
    dfail_eip:
        pop  edi
        sub  edi, dfail_eip - 0x%08X

        mov  dword ptr [edi + 0x%08X], 1
        mov  dword ptr [edi + 0x%08X], 0
    dfail_done:
        popad
        jmp  0x%08X
    """ % (IMAGE_BASE, PEND_RVA, COOL_RVA, chain_va)
    return asm(src, CAVE_FAIL_VA)


def build_tick_watchdog(chain_va, speed_cave_va, resume_va):
    """Hook B: restart the dungeon one cooldown after a defeat was latched."""
    if speed_cave_va:
        normal_resume = """
            call dtick_eip2
        dtick_eip2:
            pop  eax
            sub  eax, dtick_eip2 - 0x%08X
            add  eax, 0x%08X
            push eax
            jmp  0x%08X
        """ % (IMAGE_BASE, HOOK_TICK_RET - IMAGE_BASE, speed_cave_va)
    else:
        normal_resume = """
            mov  ecx, dword ptr [ebp - 4]
            mov  edx, dword ptr [ecx + 0x24F0]
            jmp  0x%08X
        """ % resume_va

    src = """
        pushad
        mov  eax, dword ptr [ebp - 4]
        test eax, eax
        jz   dtick_tail
        mov  esi, dword ptr [eax + 0x24F4]
        test esi, esi
        jz   dtick_tail

        call dtick_eip
    dtick_eip:
        pop  edi
        sub  edi, dtick_eip - 0x%08X

        cmp  dword ptr [edi + 0x%08X], 0
        je   dtick_check
        dec  dword ptr [edi + 0x%08X]
        jmp  dtick_tail

    dtick_check:
        cmp  dword ptr [edi + 0x%08X], 0
        je   dtick_tail
        cmp  dword ptr [esi + 0x56C], 0
        je   dtick_tail

        mov  dword ptr [edi + 0x%08X], 0
        mov  dword ptr [edi + 0x%08X], %d
        mov  dword ptr [esi + 0x5A0], 0
        mov  dword ptr [esi + 0x5B8], 0
        mov  dword ptr [esi + 0x04], 0
        mov  dword ptr [eax + 0x24FC], 0
        mov  ecx, esi
        call 0x%08X
        jmp  dtick_skip

    dtick_tail:
        popad
    %s
    dtick_skip:
        popad
        mov  ecx, dword ptr [ebp - 4]
        mov  edx, dword ptr [ecx + 0x24F0]
        jmp  0x%08X
    """ % (IMAGE_BASE, COOL_RVA, COOL_RVA, PEND_RVA,
           PEND_RVA, COOL_RVA, COOLDOWN_TICKS, DUNGEON_ENTER_VA,
           normal_resume, resume_va)
    return asm(src, CAVE_TICK_VA)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    out = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    pe = PE(src)
    raw = bytearray(pe.raw)

    # ---- hook site discovery / verification --------------------------------
    fail = pe.bytes_at(HOOK_FAIL_VA, HOOK_FAIL_LEN)
    if fail[0] != 0xE9:
        raise SystemExit("unexpected defeat hook bytes: %s" % fail.hex())
    chain_va = HOOK_FAIL_VA + 5 + int.from_bytes(fail[1:5], "little", signed=True)

    tick = pe.bytes_at(HOOK_TICK_VA, HOOK_TICK_LEN)
    if tick[0] == 0xE8:
        speed_cave_va = HOOK_TICK_VA + 5 + int.from_bytes(tick[1:5], "little",
                                                          signed=True)
        if tick[5:] != b"\x90" * 4:
            raise SystemExit("tick site already patched differently: %s"
                             % tick.hex())
        print("tick site: speed-up cave at 0x%08X (chained)" % speed_cave_va)
        tail = pe.bytes_at(SPEED_TAIL_VA, len(SPEED_TAIL_ORIG))
        if tail != SPEED_TAIL_ORIG:
            raise SystemExit("unexpected burst cave tail: %s" % tail.hex())
    else:
        speed_cave_va = 0
        if tick != HOOK_TICK_ORIG:
            raise SystemExit("unexpected tick hook bytes: %s" % tick.hex())
        print("tick site: unpatched (original instructions re-emitted)")

    print("defeat site 0x%08X chains to 0x%08X" % (HOOK_FAIL_VA, chain_va))

    # ---- grow .washd -------------------------------------------------------
    sec = None
    for s in pe.sections:
        if s["name"] == SECTION_NAME:
            sec = s
            break
    if sec is None:
        raise SystemExit("%s section not found" % SECTION_NAME)
    washd_read = washd_reader(pe)
    if sec["va"] != SECTION_VA - IMAGE_BASE:
        raise SystemExit("unexpected .washd RVA 0x%08X" % sec["va"])
    last = pe.sections[-1]
    if last["name"] != SECTION_NAME:
        raise SystemExit(".washd is not the last section")
    if last["rawptr"] + last["rawsize"] != len(raw):
        raise SystemExit(".washd is not at the end of the file")
    for va, size in ((CAVE_FAIL_VA, CAVE_TICK_VA - CAVE_FAIL_VA),
                     (CAVE_TICK_VA, DATA_VA - CAVE_TICK_VA),
                     (DATA_VA, 0x100)):
        if any(washd_read(va, size)):
            raise SystemExit("cave area 0x%08X..0x%08X is not empty"
                             % (va, va + size))

    # ---- build the caves ---------------------------------------------------
    cave_fail = build_fail_marker(chain_va)
    cave_tick = build_tick_watchdog(chain_va, speed_cave_va, HOOK_TICK_RESUME)
    if CAVE_FAIL_VA + len(cave_fail) > CAVE_TICK_VA:
        raise SystemExit("defeat cave overlaps the tick watchdog")
    if CAVE_TICK_VA + len(cave_tick) > DATA_VA:
        raise SystemExit("tick watchdog overlaps its state")
    if CAVE_TICK_VA + len(cave_tick) > 0x704E00:
        raise SystemExit("tick watchdog too large: %d bytes" % len(cave_tick))

    # ---- grow the file so the caves exist before they are written ----------
    raw += b"\x00" * (sec["rawptr"] + SECTION_RAWSIZE - len(raw))

    # ---- write: hooks ------------------------------------------------------
    def va_off(va):
        base = IMAGE_BASE + sec["va"]
        if base <= va < base + SECTION_RAWSIZE:
            return sec["rawptr"] + (va - base)
        off = pe.va2off(va)
        if off is None:
            raise SystemExit("no raw mapping for 0x%08X" % va)
        return off

    def write(va, data):
        off = va_off(va)
        raw[off:off + len(data)] = data

    def rel32(va, target, length):
        return b"\xE9" + (target - (va + 5)).to_bytes(4, "little", signed=True) \
            + b"\x90" * (length - 5)

    write(HOOK_FAIL_VA, rel32(HOOK_FAIL_VA, CAVE_FAIL_VA, HOOK_FAIL_LEN))
    write(HOOK_TICK_VA, rel32(HOOK_TICK_VA, CAVE_TICK_VA, HOOK_TICK_LEN))
    if speed_cave_va:
        write(SPEED_TAIL_VA, SPEED_TAIL_NEW)
        print("burst cave tail 0x%08X: stack-neutral ret" % SPEED_TAIL_VA)

    # ---- write: caves + state ---------------------------------------------
    write(CAVE_FAIL_VA, cave_fail)
    write(CAVE_TICK_VA, cave_tick)
    write(DATA_VA, b"\x00" * 0x40)

    # ---- write: section header --------------------------------------------
    nhdr = pe.opt + pe.sizeopt
    for i in range(pe.nsec):
        off = nhdr + i * 40
        if raw[off:off + 8].rstrip(b"\x00") == SECTION_NAME.encode():
            import struct
            struct.pack_into("<II", raw, off + 8, SECTION_VSIZE, SECTION_VA - IMAGE_BASE)
            struct.pack_into("<II", raw, off + 16, SECTION_RAWSIZE, sec["rawptr"])
            struct.pack_into("<I", raw, off + 36, SECTION_CHARS)
            print("%s: vsize 0x%X rawsize 0x%X chars 0x%08X"
                  % (SECTION_NAME, SECTION_VSIZE, SECTION_RAWSIZE,
                     SECTION_CHARS))
            break
    else:
        raise SystemExit("section header not found")

    open(out, "wb").write(bytes(raw))

    # ---- verify ------------------------------------------------------------
    v = PE(out)
    vread = washd_reader(v)
    ok = True
    s = [x for x in v.sections if x["name"] == SECTION_NAME][0]
    if (s["va"], s["vsize"], s["rawptr"], s["rawsize"], s["chars"]) != \
            (SECTION_VA - IMAGE_BASE, SECTION_VSIZE, sec["rawptr"],
             SECTION_RAWSIZE, SECTION_CHARS):
        print("FAIL section header"); ok = False
    if vread(CAVE_FAIL_VA, len(cave_fail)) != cave_fail:
        print("FAIL defeat cave"); ok = False
    if vread(CAVE_TICK_VA, len(cave_tick)) != cave_tick:
        print("FAIL tick cave"); ok = False
    if any(vread(DATA_VA, 0x40)):
        print("FAIL state block"); ok = False
    if v.bytes_at(HOOK_FAIL_VA, HOOK_FAIL_LEN)[0] != 0xE9:
        print("FAIL defeat hook"); ok = False
    if v.bytes_at(HOOK_TICK_VA, HOOK_TICK_LEN)[0] != 0xE9:
        print("FAIL tick hook"); ok = False
    if speed_cave_va and v.bytes_at(SPEED_TAIL_VA, 5) != SPEED_TAIL_NEW:
        print("FAIL burst cave tail"); ok = False
    if not ok:
        raise SystemExit("verification failed")
    import struct
    print("SizeOfImage 0x%X" % struct.unpack_from("<I", raw, pe.opt + 56)[0])

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for name, va, code in (("Hook A  defeat marker", CAVE_FAIL_VA, cave_fail),
                           ("Hook B  tick watchdog", CAVE_TICK_VA, cave_tick)):
        print("\n=== %s @ 0x%08X (%d bytes) ===" % (name, va, len(code)))
        for i in md.disasm(code, va):
            print("0x%08X  %-22s %-7s %s"
                  % (i.address, bytes(i.bytes).hex(), i.mnemonic, i.op_str))

    import hashlib
    print("\noutput:", out)
    print("size  :", len(raw))
    print("sha256:", hashlib.sha256(bytes(raw)).hexdigest())


if __name__ == "__main__":
    main()
