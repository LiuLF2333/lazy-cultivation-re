# -*- coding: utf-8 -*-
"""Emulate the v4 caves (0x703E18 burst driver, 0x703E6A log gate) with Unicorn.

Checked:
  burst cave1
    * exactly CAP ticks when the battle object exists
    * burst flag is 1 during every tick and 0 afterwards
    * 0 ticks when the battle object is NULL, 1 tick when the budget is spent
    * ebx/esi/edi preserved, ecx/edx rebuilt, control resumes at 0x4C5D6F
  log gate cave2
    * flag 0 -> real compare, message appended (ZF from [eax+0x77c])
    * flag 1 -> first message of a burst is appended, flag becomes 2
    * flag 2 -> suppressed: ZF set, eax zeroed, i.e. the following jne
                takes the "no log window" path and the append is skipped

RDTSC is emulated for real, so a build that keeps state in edx dies here
(that exact bug shipped once: rdtsc overwrote the flag pointer -> AV in game).
"""
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import *

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE

SPEED = r"D:\XiuXian\懒人修仙传.speed.exe"
CAVE1_VA = 0x703E18
CAVE2_VA = 0x703E6B
CAVE_LEN = 122
FLAG_VA = 0x703EF0

HOOK_VA = 0x4C5D66          # call site -> cave1, return address 0x4C5D6B
RESUME_VA = 0x4C5D6F
LOGCHK_VA = 0x4C5CAA        # call site -> cave2, return address 0x4C5CAF
TICK_VA = 0x48AAB0

STACK = 0x10008000
THIS = 0x20000000
MSG = 0x20000200            # "eax" object for cave2
OBJ = 0x20000400
FRAME = 0x20001000
COUNTER = 0x20000300
BUDGET_IMM = 45_000_000

ZF = 0x40


def load_blob():
    pe = PE(SPEED)
    o = pe.va2off(CAVE1_VA)
    blob = bytearray(pe.raw[o:o + CAVE_LEN])
    assert blob[-1] == 0xC3, "blob must end with ret: %s" % blob[-4:].hex()
    # RDTSC is emulated for real (it clobbers edx:eax) - the v4a build crashed
    # because the burst flag pointer lived in edx and rdtsc destroyed it.
    return blob


def make_uc(blob):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0x48A000, 0x1000)        # tick stub
    uc.mem_map(0x4C5000, 0x1000)        # hook sites / resume points
    uc.mem_map(0x703000, 0x2000)        # caves + flag
    uc.mem_map(0x10000000, 0x10000)     # stack
    uc.mem_map(0x20000000, 0x4000)      # fake objects
    uc.mem_write(CAVE1_VA, bytes(blob))
    uc.mem_write(TICK_VA, bytes.fromhex("ff0500030020") + b"\xc3")  # inc [COUNTER]; ret
    uc.mem_write(COUNTER, b"\0\0\0\0")
    return uc


def run_burst(blob, obj_ptr=OBJ, budget_patch=None):
    code = bytearray(blob)
    if budget_patch is not None:
        code = bytearray(bytes(code).replace(BUDGET_IMM.to_bytes(4, "little"),
                                             budget_patch.to_bytes(4, "little")))
    uc = make_uc(code)

    # call cave1 from the real hook address so [esp] == 0x4C5D6B
    uc.mem_write(HOOK_VA, b"\xE8" + (CAVE1_VA - (HOOK_VA + 5)).to_bytes(4, "little", signed=True))
    uc.mem_write(RESUME_VA, b"\xf4")

    uc.mem_write(THIS + 0x24F4, obj_ptr.to_bytes(4, "little"))
    uc.mem_write(THIS + 0x24F0, (0xAA).to_bytes(4, "little"))
    uc.mem_write(FRAME - 4, THIS.to_bytes(4, "little"))
    uc.mem_write(FLAG_VA, b"\x00\x00\x00\x00")

    uc.reg_write(UC_X86_REG_EBP, FRAME)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.reg_write(UC_X86_REG_EBX, 0x11111111)
    uc.reg_write(UC_X86_REG_ESI, 0x22222222)
    uc.reg_write(UC_X86_REG_EDI, 0x33333333)
    uc.reg_write(UC_X86_REG_ECX, 0x44444444)
    uc.reg_write(UC_X86_REG_EDX, 0x55555555)

    flags_seen = []
    uc.hook_add(UC_HOOK_CODE, lambda u, a, sz, usr: flags_seen.append(
        int.from_bytes(u.mem_read(FLAG_VA, 4), "little")), None, TICK_VA, TICK_VA)

    uc.emu_start(HOOK_VA, RESUME_VA, count=2_000_000)

    regs = {n: uc.reg_read(r) for n, r in
            (("ebx", UC_X86_REG_EBX), ("esi", UC_X86_REG_ESI), ("edi", UC_X86_REG_EDI),
             ("ecx", UC_X86_REG_ECX), ("edx", UC_X86_REG_EDX), ("esp", UC_X86_REG_ESP),
             ("eip", UC_X86_REG_EIP))}
    regs["ticks"] = int.from_bytes(uc.mem_read(COUNTER, 4), "little")
    regs["flag"] = int.from_bytes(uc.mem_read(FLAG_VA, 4), "little")
    regs["flag_at_ticks"] = flags_seen
    return regs


def run_gate(blob, flag, win):
    uc = make_uc(bytearray(blob))
    uc.mem_write(LOGCHK_VA, b"\xE8" + (CAVE2_VA - (LOGCHK_VA + 5)).to_bytes(4, "little", signed=True))
    uc.mem_write(LOGCHK_VA + 5, b"\x90\x90\xf4")     # nop nop + hlt at 0x4C5CB1
    uc.mem_write(FLAG_VA, flag.to_bytes(4, "little"))
    uc.mem_write(MSG + 0x77C, win.to_bytes(4, "little"))
    uc.reg_write(UC_X86_REG_EAX, MSG)
    uc.reg_write(UC_X86_REG_ESP, STACK)
    uc.emu_start(LOGCHK_VA, LOGCHK_VA + 7, count=1000)
    return dict(eip=uc.reg_read(UC_X86_REG_EIP),
                eax=uc.reg_read(UC_X86_REG_EAX),
                zf=1 if uc.reg_read(UC_X86_REG_EFLAGS) & ZF else 0,
                flag=int.from_bytes(uc.mem_read(FLAG_VA, 4), "little"))


def main():
    blob = load_blob()
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("   " + detail if detail else ""))
        ok = ok and cond

    r = run_burst(blob, budget_patch=0x7FFFFFFF)
    check("burst -> CAP ticks", r["ticks"] == 60, "ticks=%d" % r["ticks"])
    check("burst -> resumes at 0x4C5D6F", r["eip"] == RESUME_VA, "eip=%08X" % r["eip"])
    check("burst -> flag set during every tick",
          r["flag_at_ticks"] == [1] * r["ticks"], "seen=%s" % set(r["flag_at_ticks"]))
    check("burst -> flag cleared after burst", r["flag"] == 0, "flag=%d" % r["flag"])
    check("burst -> ecx = [ebp-4]", r["ecx"] == THIS, "ecx=%08X" % r["ecx"])
    check("burst -> edx = [this+0x24F0]", r["edx"] == 0xAA, "edx=%08X" % r["edx"])
    check("burst -> ebx/esi/edi preserved",
          (r["ebx"], r["esi"], r["edi"]) == (0x11111111, 0x22222222, 0x33333333),
          "ebx=%08X esi=%08X edi=%08X" % (r["ebx"], r["esi"], r["edi"]))
    check("burst -> esp balanced (call pushed 1 slot)", r["esp"] == STACK - 4,
          "esp=%08X" % r["esp"])

    r = run_burst(blob, obj_ptr=0)
    check("no battle -> 0 ticks", r["ticks"] == 0, "ticks=%d" % r["ticks"])
    check("no battle -> flag stays 0", r["flag"] == 0, "flag=%d" % r["flag"])
    check("no battle -> resumes", r["eip"] == RESUME_VA, "eip=%08X" % r["eip"])

    r = run_burst(blob, budget_patch=0)
    check("budget spent -> 1 tick", r["ticks"] == 1, "ticks=%d" % r["ticks"])
    check("budget spent -> flag cleared", r["flag"] == 0, "flag=%d" % r["flag"])

    r = run_gate(blob, flag=0, win=0x1234)
    check("gate idle+window -> real cmp (ZF=0)", r["zf"] == 0 and r["eax"] == MSG,
          "zf=%d eax=%08X" % (r["zf"], r["eax"]))
    r = run_gate(blob, flag=0, win=0)
    check("gate idle+no window -> ZF=1", r["zf"] == 1, "zf=%d" % r["zf"])

    r = run_gate(blob, flag=1, win=0x1234)
    check("gate first msg of burst -> logged, flag=2",
          r["zf"] == 0 and r["flag"] == 2 and r["eax"] == MSG,
          "zf=%d flag=%d eax=%08X" % (r["zf"], r["flag"], r["eax"]))
    r = run_gate(blob, flag=2, win=0x1234)
    check("gate suppressed -> ZF=1, eax=0, flag unchanged",
          r["zf"] == 1 and r["eax"] == 0 and r["flag"] == 2,
          "zf=%d eax=%08X flag=%d" % (r["zf"], r["eax"], r["flag"]))

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
