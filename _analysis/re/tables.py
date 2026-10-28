import io, sys, os, struct, re, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH

p = PE(PATH); d = p.data
DEC = r"D:\XiuXian\_analysis\decoded"

def rd(name):
    with open(os.path.join(DEC, name), encoding='gbk', errors='replace') as f:
        return f.read().splitlines()

print('#'*78); print('# ItemTable: type1 = 132 / 110 / 106 (full rows)')
L = rd('ItemTable.txt'); hdr = L[0].split(',')
print('HEADER:', ' | '.join(hdr))
for want in ('132','110','201','202','203','204'):
    print('-'*78); print('### type1 =', want)
    n=0
    for l in L[1:]:
        c=l.split(',')
        if len(c)<len(hdr): c += ['']*(len(hdr)-len(c))
        if c[13]==want:
            n+=1
            print('  ID=%s 名称=%s 图标=%s 分类=%s 品质=%s 等级=%s 条件=%s 判断=%s 条件值=%s 售价=%s 叠加=%s' % (
                c[0],c[1],c[2],c[3],c[6],c[7],c[8],c[9],c[10],c[11],c[12]))
            print('     type1=%s value1=%s type2=%s value2=%s  说明=%s' % (c[13],c[14],c[15],c[16],c[17]))
    print('  TOTAL', n)

print()
print('#'*78); print('# GameAttribStringTable (full)')
for l in rd('GameAttribStringTable.txt')[:95]:
    print('  ', l)
