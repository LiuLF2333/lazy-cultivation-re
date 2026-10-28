import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
sys.stdout.reconfigure(encoding="utf-8")
pe=PE(sys.argv[1])
o=pe.va2off(0x690f30)
b=pe.raw[o:o+0xa0]
print(b.hex())
for i in range(0,len(b),16):
    chunk=b[i:i+16]
    print("%08X"% (0x690f30+i), chunk.hex(), repr(chunk.decode('utf-16-le','replace')))
