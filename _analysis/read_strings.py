import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
sys.stdout.reconfigure(encoding="utf-8")
pe=PE(sys.argv[1])
for va in (0x690f44,0x690f64,0x690f6e,0x690f78,0x690f80,0x690f8c,0x690fa4,0x690900,0x690938,0x690948):
    print("%08X %r"%(va,pe.cstr(va)))
