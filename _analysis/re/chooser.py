import io, sys, os, struct, collections, importlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
import x86len; importlib.reload(x86len)
from x86len import insn_len
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']

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
            if r is not None: strs.setdefault(r+p.image_base,''.join(chr(c) for c in ch))
            i=j+2; continue
        j=i; ch=[]
        while j<b and 0x20<=d[j]<0x7f: ch.append(chr(d[j])); j+=1
        if len(ch)>=4 and j<b and d[j]==0:
            r=p.off2rva(i)
            if r is not None: strs.setdefault(r+p.image_base,''.join(ch))
            i=j+1; continue
        i+=1

def walk(start, n=60, label=''):
    o=start; out=[]
    for _ in range(n):
        if o>=TE: break
        L=insn_len(d,o)
        if L==0: break
        out.append((o,L,d[o:o+L])); o+=L
    return out

# call target of a rel32 call at offset o
def call_target(o):
    return o+5+struct.unpack_from('<i', d, o+1)[0]

PROMPTS = {
 0x007625:'选择让[%s]遗忘以下其中一个技能：',
 0x09F276:'选择派遣的宠物：',
 0x09F4D4:'选择携带的物品：',
 0x0B3DDC:'选择需要注灵的药草',
 0x0BBAAB:'请选择要洗练的准备',
 0x0AD891:'选择使用的版本：新人建议玩原版',
}
print('=== calls issued shortly after each selection prompt ===')
CHOOSERS = collections.Counter()
for site, txt in sorted(PROMPTS.items()):
    print('-'*78)
    print('prompt @0x%06X : %s' % (site, txt))
    ins = walk(site, 26)
    for (o,L,raw) in ins:
        if L==5 and raw[0]==0xE8:
            t = call_target(o)
            tag=''
            if t in strs: tag=' -> "%s"' % strs[t][:60]
            print('    0x%06X  call 0x%06X%s' % (o, t, tag))
            if t not in strs:
                CHOOSERS[t]+=1
print()
print('=== most common non-string call targets after prompts (= candidate generic chooser) ===')
for t,c in CHOOSERS.most_common(12):
    print('   0x%06X  x%d' % (t,c))
