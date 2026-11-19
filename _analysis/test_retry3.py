"""Unicorn tests for patch_dungeon_retry3.

Emulates only the injected caves, with 0x490E40 (enter dungeon) faked out, and
checks the observable side effects plus the stack/register balance of both
hooks.
"""

import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP,
                              UC_X86_REG_ECX)

SRC = r"D:\XiuXian\懒人修仙传.final.exe"

BASE = 0x400000
IMG_SIZE = 0x306000
STACK = 0x180000
STACK_SIZE = 0x10000
SCRATCH = 0x100000           # holds rt / game objects
SCRATCH_SIZE = 0x4000

HOOK_FAIL = 0x48FE4C
HOOK_TICK = 0x4C5D66
CHAIN_FAIL = 0x701B80
ENTER = 0x490E40
SPEED_CAVE = 0x703E18
SPEED_TAIL = 0x703E5D
RESUME = 0x4C5D6F
TICK_RET = 0x4C5D6B
DATA = 0x704F00

RT = SCRATCH + 0x200
GAME = SCRATCH + 0x1000

PASS, FAIL = [], []


def check(name, got, want):
    if got == want:
        PASS.append(name)
    else:
        FAIL.append("%s: got 0x%X want 0x%X" % (name, got, want))


def check_true(name, cond, detail=""):
    if cond:
        PASS.append(name)
    else:
        FAIL.append(name + (": " + detail if detail else ""))


class U:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(BASE, IMG_SIZE)
        self.uc.mem_map(STACK, STACK_SIZE)
        self.uc.mem_map(SCRATCH, SCRATCH_SIZE)
        self.img = PE(SRC)
        for s in self.img.sections:
            off = s["rawptr"]
            n = min(s["vsize"], s["rawsize"])
            self.uc.mem_write(BASE + s["va"], self.img.raw[off:off + n])
        self.entered = []
        self.uc.hook_add(UC_HOOK_CODE, self._hook)

    def _hook(self, uc, addr, size, user):
        if addr == ENTER:
            self.entered.append(uc.reg_read(UC_X86_REG_ECX))
            ret = int.from_bytes(uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 4),
                                 "little")
            uc.reg_write(UC_X86_REG_ESP, uc.reg_read(UC_X86_REG_ESP) + 4)
            uc.reg_write(UC_X86_REG_EIP, ret)

    def write(self, addr, data):
        self.uc.mem_write(addr, data)

    def u32(self, addr):
        return int.from_bytes(self.uc.mem_read(addr, 4), "little")

    def set32(self, addr, val):
        self.uc.mem_write(addr, val.to_bytes(4, "little"))

    def reset(self, rt=RT, game=GAME, target=0x1234, state=1, timer=0,
              this_obj="game"):
        self.uc.mem_write(SCRATCH, b"\x00" * SCRATCH_SIZE)
        esp = STACK + STACK_SIZE - 0x400
        ebp = esp - 0x100
        self.uc.mem_write(esp, b"\x00" * 0x200)
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, ebp)
        self.entered = []
        self.esp0 = esp
        if rt:
            self.set32(ebp - 4, rt if this_obj == "rt" else game)
            self.set32(game + 0x24F4, rt)
            self.set32(rt + 0x56C, target)
            self.set32(rt + 0x5A0, state)
            self.set32(rt + 0x5B8, timer)
            self.set32(game + 0x24FC, 99)
        return ebp

    def run(self, start, until, steps=2000):
        self.uc.emu_start(start, until, count=steps)


def test_hook_a_latches_defeat():
    u = U()
    u.reset(this_obj="rt")
    u.run(HOOK_FAIL, CHAIN_FAIL)
    check("A: eip reaches the old auto-dungeon cave", u.uc.reg_read(UC_X86_REG_EIP), CHAIN_FAIL)
    check("A: PEND latched", u.u32(DATA + 0), 1)
    check("A: COOL cleared", u.u32(DATA + 4), 0)
    check("A: stack balanced", u.uc.reg_read(UC_X86_REG_ESP), u.esp0)
    check("A: object untouched", u.u32(RT + 0x56C), 0x1234)


def test_hook_a_ignores_missing_target():
    u = U()
    u.reset(this_obj="rt", target=0)
    u.run(HOOK_FAIL, CHAIN_FAIL)
    check("A: no target -> no latch", u.u32(DATA + 0), 0)
    check("A: no target -> eip ok", u.uc.reg_read(UC_X86_REG_EIP), CHAIN_FAIL)

    u = U()
    u.reset(this_obj="rt")
    u.set32(u.uc.reg_read(UC_X86_REG_EBP) - 4, 0)
    u.run(HOOK_FAIL, CHAIN_FAIL)
    check("A: null object -> no latch", u.u32(DATA + 0), 0)
    check("A: null object -> eip ok", u.uc.reg_read(UC_X86_REG_EIP), CHAIN_FAIL)


def test_hook_b_restarts_after_defeat():
    u = U()
    u.reset()
    u.write(DATA, b"\x01\x00\x00\x00" + b"\x00\x00\x00\x00")
    u.run(HOOK_TICK, RESUME)
    check_true("B: restart called once", len(u.entered) == 1, str(len(u.entered)))
    check_true("B: restart called with ecx=rt",
               u.uc.reg_read(UC_X86_REG_EIP) == RESUME)
    check("B: PEND cleared", u.u32(DATA + 0), 0)
    check("B: COOL armed", u.u32(DATA + 4), 15)
    check("B: state reset", u.u32(RT + 0x5A0), 0)
    check("B: timer reset", u.u32(RT + 0x5B8), 0)
    check("B: stale battle dropped", u.u32(RT + 4), 0)
    check("B: auto-challenge counter reset", u.u32(GAME + 0x24FC), 0)
    check("B: burst skipped -> stack balanced", u.uc.reg_read(UC_X86_REG_ESP), u.esp0)
    check("B: burst skipped -> resume at tail", u.uc.reg_read(UC_X86_REG_EIP), RESUME)
    # the restart must be issued as __thiscall with ecx == [game+0x24F4] == rt
    check_true("B: restart uses __thiscall on rt", u.entered == [RT],
               str([hex(c) for c in u.entered]))


def test_hook_b_counts_down():
    u = U()
    u.reset()
    u.write(DATA, b"\x01\x00\x00\x00" + (5).to_bytes(4, "little"))
    u.run(HOOK_TICK, SPEED_CAVE)
    check("B: cooldown ticks down", u.u32(DATA + 4), 4)
    check("B: PEND kept while cooling", u.u32(DATA + 0), 1)
    check_true("B: no restart while cooling", len(u.entered) == 0)
    check("B: enters the burst cave", u.uc.reg_read(UC_X86_REG_EIP), SPEED_CAVE)
    esp = u.uc.reg_read(UC_X86_REG_ESP)
    check("B: fake return address on stack",
          int.from_bytes(u.uc.mem_read(esp, 4), "little"), TICK_RET)


def test_hook_b_idle_is_cheap():
    u = U()
    u.reset()
    u.run(HOOK_TICK, SPEED_CAVE)
    check_true("B: nothing pending -> no restart", len(u.entered) == 0)
    check("B: state untouched", u.u32(RT + 0x5A0), 1)
    check("B: timer untouched", u.u32(RT + 0x5B8), 0)
    check("B: burst still runs", u.uc.reg_read(UC_X86_REG_EIP), SPEED_CAVE)
    check("B: stack balanced", u.uc.reg_read(UC_X86_REG_ESP), u.esp0 - 4)


def test_hook_b_no_target():
    u = U()
    u.reset(target=0)
    u.write(DATA, b"\x01\x00\x00\x00" + b"\x00\x00\x00\x00")
    u.run(HOOK_TICK, SPEED_CAVE)
    check_true("B: no target -> no restart", len(u.entered) == 0)
    check("B: PEND survives", u.u32(DATA + 0), 1)


def test_hook_b_null_objects():
    u = U()
    u.reset(rt=None)
    u.write(DATA, b"\x01\x00\x00\x00" + b"\x00\x00\x00\x00")
    u.run(HOOK_TICK, SPEED_CAVE)
    check_true("B: null game object -> no crash", len(u.entered) == 0)
    check("B: null -> burst still runs", u.uc.reg_read(UC_X86_REG_EIP), SPEED_CAVE)
    check("B: null -> stack balanced", u.uc.reg_read(UC_X86_REG_ESP), u.esp0 - 4)

    u = U()
    ebp = u.reset()
    u.set32(GAME + 0x24F4, 0)
    u.write(DATA, b"\x01\x00\x00\x00" + b"\x00\x00\x00\x00")
    u.run(HOOK_TICK, SPEED_CAVE)
    check_true("B: null dungeon object -> no crash", len(u.entered) == 0)
    check("B: null rt -> PEND survives", u.u32(DATA + 0), 1)


def test_burst_tail_returns():
    # the burst cave ends with `ret` so the `call` that enters it is balanced:
    # esp must come back to the slot holding 0x4C5D6B and control must fall
    # through the four nops into 0x4C5D6F.
    u = U()
    esp = STACK + STACK_SIZE - 0x400
    u.uc.mem_write(esp - 0x100, b"\x00" * 0x200)
    u.uc.mem_write(esp, TICK_RET.to_bytes(4, "little"))
    u.uc.reg_write(UC_X86_REG_ESP, esp)
    u.uc.reg_write(UC_X86_REG_EBP, esp - 0x100)
    u.set32(esp - 0x104, GAME)
    u.set32(GAME + 0x24F0, 0xABC0)
    u.run(SPEED_TAIL, RESUME)
    check("tail: esp restored", u.uc.reg_read(UC_X86_REG_ESP), esp + 4)
    check_true("tail: eip continues past the hook",
               u.uc.reg_read(UC_X86_REG_EIP) == RESUME)


def main():
    for fn in (test_hook_a_latches_defeat,
               test_hook_a_ignores_missing_target,
               test_hook_b_restarts_after_defeat,
               test_hook_b_counts_down,
               test_hook_b_idle_is_cheap,
               test_hook_b_no_target,
               test_hook_b_null_objects,
               test_burst_tail_returns):
        try:
            fn()
        except Exception as exc:            # noqa: BLE001
            FAIL.append("%s raised %s: %s" % (fn.__name__, type(exc).__name__, exc))
    print("passed %d checks" % len(PASS))
    for line in FAIL:
        print("FAIL", line)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
