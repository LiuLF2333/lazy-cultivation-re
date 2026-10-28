# -*- coding: utf-8 -*-
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_OPT_SYNTAX_INTEL
import struct

BASE = 0x6FD000
asm = r"""
start:
    call geteip
geteip:
    pop ebx
    sub ebx, geteip
    mov eax, [ebx + 0x645638]
    call dword ptr [ebx + 0x645638]
    lea eax, [ebx + str_hello]
    push eax
    push str_hello
    mov ecx, msg_paint
    cmp eax, 0x0F
    jne skip
skip:
    call sub1
    jmp start
sub1:
    ret
str_hello:
    db 0x41, 0x00
msg_paint equ 0x0F
"""
ks = Ks(KS_ARCH_X86, KS_MODE_32)
ks.syntax = KS_OPT_SYNTAX_INTEL
enc, cnt = ks.asm(asm, BASE)
print("count", cnt, "len", len(enc))
b = bytes(enc)
print(b.hex())
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md = Cs(CS_ARCH_X86, CS_MODE_32)
for i in md.disasm(b, BASE):
    print("  0x%08X  %-18s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
