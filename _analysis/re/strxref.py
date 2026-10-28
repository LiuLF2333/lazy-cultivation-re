import io, sys, os, struct, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']
def off2va(o):
    r=p.off2rva(o); return None if r is None else r+p.image_base
def va2off(v): return p.rva2off(v-p.image_base)

# ---- index all string starts (VA -> text, offset) ----
strs={}
for s in p.sections:
    a,b=s['rawptr'],s['rawptr']+s['rawsize']; i=a
    while i<b:
        j=i; ch=[]
        while j+1<b:
            cp=d[j]|(d[j+1]<<8)
            if cp==0: break
            if (0x20<=cp<0x7f) or (0x4e00<=cp<=0x9fff) or (0x3000<=cp<=0x303f) or (0xff00<=cp<=0xffef) or cp in (0x2026,0x2014,0x2018,0x2019,0x201c,0x201d):
                ch.append(cp); j+=2
            else: ch=None; break
        if ch and len(ch)>=2 and j+1<b and d[j]==0 and d[j+1]==0:
            r=p.off2rva(i)
            if r is not None: strs.setdefault(r+p.image_base, ''.join(chr(c) for c in ch))
            i=j+2; continue
        j=i; ch=[]
        while j<b and 0x20<=d[j]<0x7f: ch.append(chr(d[j])); j+=1
        if len(ch)>=4 and j<b and d[j]==0:
            r=p.off2rva(i)
            if r is not None: strs.setdefault(r+p.image_base,''.join(ch))
            i=j+1; continue
        i+=1

# ---- global xref: dword in .text equal to string VA, validated as push/mov imm ----
xref = collections.defaultdict(list)
i = TS
while i < TE-4:
    v = struct.unpack_from('<I', d, i)[0]
    if v in strs:
        prev = d[i-1] if i > TS else 0
        if prev == 0x68:
            xref[v].append((i-1,'push imm32'))
        elif 0xB8 <= prev <= 0xBF:
            xref[v].append((i-1,'mov r32,imm32'))
        elif prev == 0x50+((prev-0x50)) :
            pass
        else:
            # could be part of a mov r/m32, imm32 (C7 /0) or a data dword
            xref[v].append((i,'raw-dword-in-.text'))
    i += 1

print('=== CODE XREFS TO ATTRIBUTE / ITEM-USE STRINGS ===')
KEYS = ['无效属性','属性异常','重构角色属性','没有可保存的属性','当前属性','新属性',
        '没有可以洗练的属性','无洗练属性','随机结果','选择让','请选择要洗练','选择派遣',
        '选择携带','选择需要注灵','选择使用','根骨[','机缘[','加载属性字符串时出错',
        '加载装备属性生成配置文件出错','所有基础属性增加20点','领悟属性','属性异常，无领悟属性']
for k in KEYS:
    print('-'*78)
    hits = [(va,t) for va,t in strs.items() if k in t]
    for va, t in sorted(hits, key=lambda x:x[0]):
        sites = xref.get(va, [])
        print('  STR 0x%08X (rva 0x%06X) file=0x%06X  %r' % (va, va-p.image_base, va2off(va) or 0, t[:80]))
        if not sites:
            print('      -> NO code xref found (maybe referenced via table)')
        for so, kind in sites[:8]:
            print('      -> code 0x%06X (rva 0x%06X)  %s' % (so, so-TS+TEXT['vaddr'], kind))
print()
print('total strings indexed:', len(strs), ' strings with >=1 xref:', len(xref))
