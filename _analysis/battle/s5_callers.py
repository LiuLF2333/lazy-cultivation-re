# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE
p = PE(r"D:\XiuXian\懒人修仙传.exe")
for target in [0x48FB00, 0x48FF70, 0x490500, 0x48F7C0, 0x48E800, 0x4906E0, 0x490A30, 0x490A60, 0x490A90]:
    sites = p.find_calls_to(target)
    print("callers of 0x%08X: %d" % (target, len(sites)))
    for s in sites:
        print("   0x%08X" % s)
