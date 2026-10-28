import sys, io, os, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
OUT = r"D:\XiuXian\_analysis\re\out"

TERMS = ['选择','请选择','属性','根骨','机缘','悟性','确定','取消','随机','自选','列表','下拉',
         '资质','灵根','体质','神识','力量','敏捷','智力','魅力','幸运','气运','福缘',
         '请选择属性','选择属性','增加属性','属性选择','随机属性','分配','加点','重置']

for fn in ['utf16_cjk_strings.txt','ascii_strings.txt']:
    path = os.path.join(OUT,fn)
    if not os.path.exists(path): continue
    print('#'*70); print('### FILE', fn, os.path.getsize(path),'bytes')
    lines = open(path,encoding='utf-8').read().splitlines()
    for t in TERMS:
        m = [l for l in lines if t in l.split('\t',3)[-1]]
        print('%-10s %4d  %s' % (t, len(m), (m[0].split('\t')[3][:70] if m else '')))
    print()
