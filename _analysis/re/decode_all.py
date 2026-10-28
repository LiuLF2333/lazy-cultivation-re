import io, sys, os, struct, importlib, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
import x86len; importlib.reload(x86len)
from x86len import insn_len
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']

# find function starts (after >=2 0xCC pad)
starts=[]; i=TS
while i<TE-1:
    if d[i]==0xCC:
        j=i
        while j<TE and d[j]==0xCC: j+=1
        if j-i>=2 and j<TE: starts.append(j)
        i=j
    else: i+=1
starts=[s for s in starts if s<TE]
print('function starts:', len(starts))

fails=collections.Counter(); total_ok=0; total_bad=0
bad_examples=[]
allins=[]   # (offset, len)
for k,st in enumerate(starts):
    end = starts[k+1] if k+1<len(starts) else TE
    o=st
    while o<end:
        L=insn_len(d,o)
        if L==0 or o+L>end:
            total_bad+=1
            key=d[o]
            fails[key]+=1
            if len(bad_examples)<40: bad_examples.append((o,d[o:o+10]))
            o+=1
            continue
        total_ok+=1
        allins.append((o,L))
        o+=L
print('decoded insns:', total_ok, ' decode failures:', total_bad)
print('failure rate: %.3f%%' % (100.0*total_bad/(total_ok+total_bad)))
print()
print('top failing first-bytes:')
for b,c in fails.most_common(25):
    print('   0x%02X  x%d' % (b,c))
print()
print('first failure examples (offset : bytes):')
for o,bs in bad_examples[:30]:
    print('   0x%06X  %s' % (o, ' '.join('%02X'%x for x in bs)))
