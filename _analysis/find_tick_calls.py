import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
pe=PE(sys.argv[1])
for t in (0x4A0CD0,):
    print("calls to %08X:"%t)
    for s in pe.find_calls_to(t): print("  %08X"%s)
