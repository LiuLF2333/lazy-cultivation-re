# -*- coding: utf-8 -*-
"""Unit-test the position independent leak-fix caves with Unicorn.

cave_a is entered by `call` from 0x46093D (the instruction that used to be
`mov [ebp-0x1D4],eax`).  It must perform that store, remember the handle in the
patch slot (address derived from the return address) and return to 0x460942.

cave_b is entered by `call` from 0x4610FE.  It must DeleteDC the remembered
handle once, clear the slot, rebuild ecx = &[ebp-0x184] and return to 0x461103.
"""
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import *

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\XiuXian\懒人修仙传.speed2.exe"
CAVE_A = 0x703E94
CAVE_B = 0x703EA8
TMP = 0x703EE0
DELCNT = 0x700200
STUB_DELETE = 0x700110
STACK = 0x10008000
EBP = 0x30001000
FAKE_DC = 0x00AB1234
RET_A = 0x460942
RET_B = 0x461103


def load():
    pe = PE(EXE)
    o = pe.va2off(CAVE_A)
    return bytes(pe.raw[o:o + 0x40])


def setup():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0x703000, 0x1000)     # caves + slot
    uc.mem_map(0x700000, 0x1000)     # delete stub + counter
    uc.mem_map(0x460000, 0x2000)     # return targets
    uc.mem_map(0x645000, 0x1000)     # "IAT" page reached by the cave's delta
    uc.mem_map(0x30000000, 0x2000)   # frame (ebp)
    uc.mem_map(0x10000000, 0x10000)  # stack
    uc.mem_write(STUB_DELETE, bytes.fromhex("ff0500027000") + b"\xC2\x04\x00")
    uc.mem_write(DELCNT, b"\0\0\0\0")
    uc.mem_write(RET_A, b"\xf4")
    uc.mem_write(RET_B, b"\xf4")
    return uc


def run_cave_a(code):
    uc = setup()
    uc.mem_write(CAVE_A, code[:CAVE_B - CAVE_A])
    uc.reg_write(UC_X86_REG_EBP, EBP)
    uc.reg_write(UC_X86_REG_EAX, FAKE_DC)
    uc.reg_write(UC_X86_REG_ESP, STACK - 4)
    uc.mem_write(STACK - 4, RET_A.to_bytes(4, "little"))
    uc.emu_start(CAVE_A, RET_A, count=1000)
    return dict(eip=uc.reg_read(UC_X86_REG_EIP), esp=uc.reg_read(UC_X86_REG_ESP),
                local=int.from_bytes(uc.mem_read(EBP - 0x1D4, 4), "little"),
                tmp=int.from_bytes(uc.mem_read(TMP, 4), "little"))


def run_cave_b(code, tmp_value):
    uc = setup()
    uc.mem_write(CAVE_B, code[CAVE_B - CAVE_A:])
    uc.mem_write(0x6451B8, STUB_DELETE.to_bytes(4, "little"))
    uc.reg_write(UC_X86_REG_EBP, EBP)
    uc.reg_write(UC_X86_REG_ESP, STACK - 4)
    uc.mem_write(STACK - 4, RET_B.to_bytes(4, "little"))
    uc.mem_write(TMP, tmp_value.to_bytes(4, "little"))
    uc.emu_start(CAVE_B, RET_B, count=1000)
    return dict(eip=uc.reg_read(UC_X86_REG_EIP), esp=uc.reg_read(UC_X86_REG_ESP),
                ecx=uc.reg_read(UC_X86_REG_ECX),
                tmp=int.from_bytes(uc.mem_read(TMP, 4), "little"),
                dels=int.from_bytes(uc.mem_read(DELCNT, 4), "little"))


def main():
    code = load()
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("   " + detail if detail else ""))
        ok = ok and cond

    r = run_cave_a(code)
    check("cave_a returns to 0x460942", r["eip"] == RET_A, "eip=%08X" % r["eip"])
    check("cave_a stack balanced", r["esp"] == STACK, "esp=%08X" % r["esp"])
    check("cave_a wrote [ebp-0x1D4]", r["local"] == FAKE_DC, "%08X" % r["local"])
    check("cave_a remembered the DC", r["tmp"] == FAKE_DC, "tmp=%08X" % r["tmp"])

    r = run_cave_b(code, FAKE_DC)
    check("cave_b returns to 0x461103", r["eip"] == RET_B, "eip=%08X" % r["eip"])
    check("cave_b stack balanced", r["esp"] == STACK, "esp=%08X" % r["esp"])
    check("cave_b calls DeleteDC once", r["dels"] == 1, "calls=%d" % r["dels"])
    check("cave_b clears the slot", r["tmp"] == 0, "tmp=%d" % r["tmp"])
    check("cave_b rebuilds ecx", r["ecx"] == (EBP - 0x184) & 0xFFFFFFFF, "ecx=%08X" % r["ecx"])

    r = run_cave_b(code, 0)
    check("cave_b empty slot skips DeleteDC", r["dels"] == 0, "calls=%d" % r["dels"])
    check("cave_b empty slot resumes", r["eip"] == RET_B, "eip=%08X" % r["eip"])

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
