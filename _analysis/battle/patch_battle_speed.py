# -*- coding: utf-8 -*-
"""Patch 懒人修仙传.exe: run the battle state machine far faster than vanilla
while keeping the UI thread responsive.

Timing chain (static):
  * main window timer 0x3E9 fires every 100 ms; case entry 0x4C5D17;
  * that case does += 10 on [game+0x24F0] and only when it reaches
    [game+0x24F8] == 100 (once per second) calls 0x4C2A90;
  * 0x4C2A90 calls the battle frame machine 0x48AAB0 exactly once;
  * a round is phase1 execute / phase2 aftermath / phase0 wait N ticks with
    N = 3*round + rand()%5 (<=30), and every wait tick formats a battle-log
    line via 0x416F90 (id 0x39) -> 0x416EF0 -> 0x4C5CA0 -> 0x45AD70.

Measured reality (user, vanilla+hook builds):
  * 12 battle ticks/s  -> ~100 kills/min, perfectly smooth;
  * ~105 battle ticks/s (old v1 burst) -> ~900 kills/min but laggy.
  The dominant per-tick cost is the battle-log text append (0x4C5CA0), whose
  price grows with the log length, so pure tick-rate scaling hits a wall.

v4 therefore does three things:

  1. 0x48AB42  `7e 33` (jle)  ->  `eb 33` (jmp)
     Removes the between-round wait entirely (a round = 3 ticks, no log spam).

  2. 0x4C5D66  9 bytes -> `call cave1` + 4*nop  (re-emulated afterwards)
     Runs a budgeted burst of ticks on EVERY 100 ms timer fire (10 bursts/s)
     instead of once per second.  Burst is capped by CAP ticks and by a rdtsc
     budget (~15 ms) so it can never hog the message loop for long; the burst
     ends immediately when the battle object is gone.

  3. 0x4C5CAA  7 bytes (`cmp dword [eax+0x77c],0`) -> `call cave2` + 2*nop
     While a burst is running, the battle-log text append is skipped except
     for the first message of each burst (that keeps the log visibly alive at
     ~10 lines/s and removes ~all of the per-tick cost).  Set ZF on the skip
     path so the following `jne` behaves like the original "no log window".

  .wash must become writable for the one dword of burst state, so the .wash
  section header gets IMAGE_SCN_MEM_WRITE (chars 0x60000020 -> 0xE0000020).
  All injected code is position independent (rel32 / ebp / call-pop), because
  the image is /DYNAMICBASE and may be rebased.
"""
import hashlib
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

DEFAULT_SRC = r"D:\XiuXian\懒人修仙传.exe"
SRC = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SRC
OUT = sys.argv[1] if len(sys.argv) > 1 else r"D:\XiuXian\懒人修仙传.speed.exe"

WAIT_VA = 0x48AB42          # 7E 33            jle 0x48AB77 (wait branch)
WAIT_ORIG = bytes.fromhex("7e33")
WAIT_NEW = bytes.fromhex("eb33")     # jmp 0x48AB77 (start next round now)

HOOK_VA = 0x4C5D66          # inside WM_TIMER case 0x3E9, runs every 100 ms
HOOK_LEN = 9
HOOK_ORIG = bytes.fromhex("8b4dfc8b91f0240000")   # mov ecx,[ebp-4]; mov edx,[ecx+0x24F0]
RESUME_VA = 0x4C5D6F        # add edx, 0xa

LOGCHK_VA = 0x4C5CAA        # cmp dword [eax+0x77c], 0   (log window present?)
LOGCHK_LEN = 7
LOGCHK_ORIG = bytes.fromhex("83b87c07000000")
LOGCHK_RESUME = 0x4C5CB1    # jne 0x4C5CB5

TICK_VA = 0x48AAB0          # battle frame machine (__thiscall, ecx = battle obj)
SING_VA = 0x48E800          # returns the game-state singleton (0 if none)
HOUSE_VA = 0x47EE70         # per-frame housekeeping: animation player + screen fx
CAVE_VA = 0x703E18          # zero-filled tail of .wash (CODE|EXECUTE|READ)
FLAG_VA = 0x703EF0          # burst state: 0 idle, 1 burst started, 2 logged once

# ---- GDI handle leak fix (pre-existing game bug, amplified by the speed-up) --
# 0x4608E0 creates a memory DC at 0x460937 into [ebp-0x1D4] and never releases
# it; measured leak ~9 handles/s while fighting -> the 10000 GDI handle limit is
# hit after ~30 min and the whole screen goes garbled.
LEAK_SITE_VA = 0x46093D
LEAK_SITE_ORIG = bytes.fromhex("89852cfeffff")      # mov [ebp-0x1D4], eax
LEAK_RESUME1 = 0x460943
LEAK_EXIT_VA = 0x4610FE
LEAK_EXIT_ORIG = bytes.fromhex("8d8d7cfeffff")      # lea ecx,[ebp-0x184]
LEAK_RESUME2 = 0x461104
LEAK_TMP_VA = 0x703EE0      # slot holding the freshly created DC
DC_IAT = 0x6451AC           # CreateCompatibleDC
DELDC_IAT = 0x6451B8        # DeleteDC

CAP = 60                    # max ticks per 100 ms burst (10 bursts / second)
BUDGET = 45_000_000         # max rdtsc cycles per burst (~15 ms at 3 GHz)
WITH_HOUSE = False          # also run 0x47EE70 (animation/screen-fx stepper)
                            # after every tick, like vanilla 0x4C2A90 does.
                            # Off = fastest (shipped build); on = exact 1:1
                            # frame semantics with the original game.


def _asm(src, addr):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    enc, _ = ks.asm(src, addr=addr)
    return bytes(enc)


def build_cave1(cave_va):
    """Burst driver.  The flag address is derived from our own return address,
    so the code stays position independent if the image is rebased.

    NOTE: the flag pointer must NOT live in edx - rdtsc overwrites edx:eax.
    It lives in edi (callee saved) and 'this' is re-read from [ebp-4] instead.
    """
    house = """
        call %d
        test eax, eax
        je   after_house
        mov  ecx, eax
        call %d
    after_house:""" % (SING_VA, HOUSE_VA) if WITH_HOUSE else ""
    src = """
        push ebx
        push esi
        push edi
        mov  edi, dword ptr [esp + 12]
        add  edi, %d
        mov  dword ptr [edi], 1
        rdtsc
        mov  ebx, eax
        mov  esi, %d
    next_tick:
        mov  eax, dword ptr [ebp - 4]
        mov  ecx, dword ptr [eax + 0x24f4]
        test ecx, ecx
        je   burst_done
        call %d
        %s
        rdtsc
        sub  eax, ebx
        cmp  eax, %d
        jae  burst_done
        dec  esi
        jne  next_tick
    burst_done:
        mov  dword ptr [edi], 0
        pop  edi
        pop  esi
        pop  ebx
        mov  ecx, dword ptr [ebp - 4]
        mov  edx, dword ptr [ecx + 0x24f0]
        jmp  %d
    """ % (FLAG_VA - (HOOK_VA + 5), CAP, TICK_VA, house, BUDGET, RESUME_VA)
    return _asm(src, cave_va)


def build_cave2(cave_va):
    src = """
        mov  edx, dword ptr [esp]
        add  edx, %d
        mov  ecx, dword ptr [edx]
        cmp  ecx, 1
        je   first_of_burst
        test ecx, ecx
        jne  suppressed
    normal_check:
        cmp  dword ptr [eax + 0x77c], 0
        ret
    first_of_burst:
        mov  dword ptr [edx], 2
        jmp  normal_check
    suppressed:
        xor  eax, eax
        ret
    """ % (FLAG_VA - (LOGCHK_VA + 5),)
    return _asm(src, cave_va)


def build_leakfix(cave_a_va):
    """Two position independent caves that give 0x4608E0 its missing DeleteDC.

    All addresses come from the return address that the hook's `call` leaves on
    the stack, so the patch keeps working no matter where the image is loaded
    (ASLR stays enabled - the exe does not need /DYNAMICBASE removed).
    """
    src_a = """
        mov  dword ptr [ebp - 0x1d4], eax
        mov  edx, dword ptr [esp]
        add  edx, %d
        mov  dword ptr [edx], eax
        ret
    """ % (LEAK_TMP_VA - (LEAK_SITE_VA + 5),)
    cave_a = _asm(src_a, cave_a_va)
    cave_b_va = (cave_a_va + len(cave_a) + 3) & ~3
    src_b = """
        mov  edx, dword ptr [esp]
        mov  ecx, dword ptr [edx + %d]
        test ecx, ecx
        je   no_dc
        mov  dword ptr [edx + %d], 0
        push ecx
        call dword ptr [edx + %d]
    no_dc:
        lea  ecx, [ebp - 0x184]
        ret
    """ % (LEAK_TMP_VA - (LEAK_EXIT_VA + 5),
           LEAK_TMP_VA - (LEAK_EXIT_VA + 5),
           DELDC_IAT - (LEAK_EXIT_VA + 5))
    cave_b = _asm(src_b, cave_b_va)
    return cave_a, cave_b, cave_b_va


def main():
    pe = PE(SRC)
    raw = bytearray(pe.raw)

    def check(va, orig, what):
        o = pe.va2off(va)
        cur = bytes(raw[o:o + len(orig)])
        if cur != orig:
            raise SystemExit("%s site 0x%08X mismatch: %s" % (what, va, cur.hex(" ")))
        return o

    off_wait = check(WAIT_VA, WAIT_ORIG, "wait")
    off_hook = check(HOOK_VA, HOOK_ORIG, "burst hook")
    off_log = check(LOGCHK_VA, LOGCHK_ORIG, "log check")

    cave1 = build_cave1(CAVE_VA)
    cave2 = build_cave2(CAVE_VA + len(cave1))
    blob = cave1 + cave2
    off_cave = pe.va2off(CAVE_VA)
    need = (FLAG_VA + 4) - CAVE_VA
    if any(raw[off_cave:off_cave + need]):
        raise SystemExit("cave range 0x%08X..0x%08X is not free" % (CAVE_VA, FLAG_VA + 4))

    # rel32 hooks
    raw[off_hook:off_hook + 5] = b"\xE8" + struct.pack("<i", CAVE_VA - (HOOK_VA + 5))
    raw[off_hook + 5:off_hook + HOOK_LEN] = b"\x90" * (HOOK_LEN - 5)

    cave2_va = CAVE_VA + len(cave1)
    raw[off_log:off_log + 5] = b"\xE8" + struct.pack("<i", cave2_va - (LOGCHK_VA + 5))
    raw[off_log + 5:off_log + LOGCHK_LEN] = b"\x90" * (LOGCHK_LEN - 5)

    raw[off_wait:off_wait + 2] = WAIT_NEW
    raw[off_cave:off_cave + len(blob)] = blob

    # ---- GDI leak fix ------------------------------------------------
    leak_a_va = (CAVE_VA + len(blob) + 3) & ~3
    cave_a, cave_b, cave_b_va = build_leakfix(leak_a_va)
    if cave_b_va + len(cave_b) > LEAK_TMP_VA:
        raise SystemExit("leak-fix caves do not fit (need up to 0x%08X)"
                         % (cave_b_va + len(cave_b)))
    raw[pe.va2off(leak_a_va):pe.va2off(leak_a_va) + len(cave_a)] = cave_a
    raw[pe.va2off(cave_b_va):pe.va2off(cave_b_va) + len(cave_b)] = cave_b

    off_ls = check(LEAK_SITE_VA, LEAK_SITE_ORIG, "leak create")
    raw[off_ls:off_ls + 5] = b"\xE8" + struct.pack("<i", leak_a_va - (LEAK_SITE_VA + 5))
    raw[off_ls + 5] = 0x90
    off_le = check(LEAK_EXIT_VA, LEAK_EXIT_ORIG, "leak exit")
    raw[off_le:off_le + 5] = b"\xE8" + struct.pack("<i", cave_b_va - (LEAK_EXIT_VA + 5))
    raw[off_le + 5] = 0x90

    # ASLR is left enabled: every injected instruction is position independent
    # (rel32 / [ebp-x] / addresses derived from the return address), so the
    # patch survives relocation by the loader.

    # make .wash writable (the burst flag lives there)
    sh = pe.opt + pe.sizeopt
    for i in range(pe.nsec):
        o = sh + i * 40
        name = raw[o:o + 8].rstrip(b"\x00").decode("latin1")
        if name == ".wash":
            chars = struct.unpack_from("<I", raw, o + 36)[0]
            struct.pack_into("<I", raw, o + 36, chars | 0x80000000)
            print(".wash chars 0x%08X -> 0x%08X" % (chars, chars | 0x80000000))
            break
    else:
        raise SystemExit(".wash section not found")

    open(OUT, "wb").write(bytes(raw))
    print("cave1: %d bytes @ 0x%08X (CAP=%d, budget=%d)"
          % (len(cave1), CAVE_VA, CAP, BUDGET))
    print("cave2: %d bytes @ 0x%08X (log gate, flag @ 0x%08X)"
          % (len(cave2), cave2_va, FLAG_VA))
    print("hook 0x%08X -> 0x%08X : %s"
          % (HOOK_VA, CAVE_VA, bytes(raw[off_hook:off_hook + HOOK_LEN]).hex(" ")))
    print("log  0x%08X -> 0x%08X : %s"
          % (LOGCHK_VA, cave2_va, bytes(raw[off_log:off_log + LOGCHK_LEN]).hex(" ")))
    print("wait 0x%08X : %s" % (WAIT_VA, bytes(raw[off_wait:off_wait + 2]).hex(" ")))
    print("output:", OUT)
    print("sha256:", hashlib.sha256(bytes(raw)).hexdigest())


if __name__ == "__main__":
    main()
