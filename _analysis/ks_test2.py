# -*- coding: utf-8 -*-
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_OPT_SYNTAX_INTEL
import traceback

BASE = 0x6FD000
ks = Ks(KS_ARCH_X86, KS_MODE_32)
ks.syntax = KS_OPT_SYNTAX_INTEL

tests = {
 "basic": "nop\nret\n",
 "label_disp": "start:\ncall lbl\nlbl:\npop ebx\nsub ebx, lbl\nmov eax, [ebx + 0x645638]\n",
 "lea_label": "start:\nlea eax, [ebx + data]\ndata:\ndb 0x41, 0x00\n",
 "push_label": "push str1\nstr1:\ndb 0x41,0x00\n",
 "call_iat": "call dword ptr [ebx + 0x645638]\n",
 "jcc_near": "cmp eax, 15\nje lbl\nnop\nlbl:\nret\n",
 "dbonly": "db 1,2,3,4\n",
 "equ": "X equ 5\nmov eax, X\n",
 "dd": "dd 0x12345678\n",
}
for name, src in tests.items():
    try:
        enc, cnt = ks.asm(src, BASE)
        print("%-12s OK  %s" % (name, bytes(enc).hex()))
    except Exception as e:
        print("%-12s FAIL %s" % (name, e))
