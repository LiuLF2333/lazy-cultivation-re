# -*- coding: utf-8 -*-
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_OPT_SYNTAX_INTEL
BASE = 0x6FD000
ks = Ks(KS_ARCH_X86, KS_MODE_32); ks.syntax = KS_OPT_SYNTAX_INTEL
tests = {
 "lea_datalabel": "start:\nlea eax, [ebx + str1]\nret\nstr1:\n.byte 0x41,0x00\n",
 "push_datalabel": "start:\npush str1\nret\nstr1:\n.byte 0x41,0x00\n",
 "mov_mem_imm_label": "mov dword ptr [ebp - 0x7C], str1\nstr1:\n.byte 1\n",
 "rep_stosd": "lea edi,[ebp-0x30]\nxor eax,eax\nmov ecx,8\nrep stosd\n",
 "ret16": "ret 0x10\n",
 "imul_none": "cmp eax, 0x0F\n",
 "sar": "sar eax, 16\n",
 "div": "xor edx,edx\nmov ecx,5\ndiv ecx\n",
 "push_ptr": "push dword ptr [ebp - 0xA4]\n",
 "je_local": "start:\ncmp eax,1\nje .done\n.done:\nret\n",
 "jmp_label": "jmp wasn\nwasn:\nret\n",
}
for name, src in tests.items():
    try:
        enc, cnt = ks.asm(src, BASE)
        print("%-20s OK  %s" % (name, bytes(enc).hex()))
    except Exception as e:
        print("%-20s FAIL %s" % (name, e))
