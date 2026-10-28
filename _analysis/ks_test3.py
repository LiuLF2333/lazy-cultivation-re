# -*- coding: utf-8 -*-
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_OPT_SYNTAX_INTEL
BASE = 0x6FD000
ks = Ks(KS_ARCH_X86, KS_MODE_32)
ks.syntax = KS_OPT_SYNTAX_INTEL
tests = {
 "lea_codelabel": "start:\nlea eax, [ebx + end]\nnop\nend:\nret\n",
 "byte": ".byte 0x41, 0x00\n",
 "db_inline": "start:\nret\nstr1:\ndb 65,0\n",
 "dd": ".long 0x11223344\n",
 "label_mem": "start:\nmov eax, str1\nstr1:\nret\n",
 "offset": "start:\nmov eax, offset str1\nret\nstr1:\nnop\n",
}
for name, src in tests.items():
    try:
        enc, cnt = ks.asm(src, BASE)
        print("%-16s OK  %s" % (name, bytes(enc).hex()))
    except Exception as e:
        print("%-16s FAIL %s" % (name, e))
