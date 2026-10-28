import io, sys, os, struct, collections, importlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r"D:\XiuXian\_analysis\re")
from peparse import PE, PATH
import x86len; importlib.reload(x86len)
from x86len import insn_len
p = PE(PATH); d = p.data
TEXT = next(s for s in p.sections if s['name']=='.text')
TS,TE = TEXT['rawptr'], TEXT['rawptr']+TEXT['rawsize']

def find_func_start(off, back=0x4000):
    """Walk back to the last 0xCC-pad / ret boundary before off."""
    a = max(TS, off-back)
    # prefer int3 padding
    for i in range(off-1, a, -1):
        if d[i]==0xCC and d[i+1]==0xCC and (i<TS or d[i-1]!=0xCC):
            return i+1
    return None

def linear_disasm(start, maxlen=0x3000):
    insns=[]; o=start; end=min(TE, start+maxlen)
    while o < end:
        L = insn_len(d,o)
        if L==0 or o+L>end: break
        insns.append((o,L,d[o:o+L])); o+=L
    return insns, o

# ---- index strings ----
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
print('strings:', len(strs))

def show_at(push_site, title, span=0x260):
    st = find_func_start(push_site)
    print('='*82); print('### %s' % title)
    print('### push site 0x%06X (rva 0x%06X); inferred function start 0x%X' % (
        push_site, push_site-TS+TEXT['vaddr'], st if st else 0))
    if st is None:
        st = max(TS, push_site-0x180)
    insns, endo = linear_disasm(st, span)
    for (o,L,raw) in insns:
        mark = '  <<<< HERE' if o == push_site else ''
        note = ''
        if L >= 5 and raw[0] in (0x68,) :
            v = struct.unpack_from('<I',raw,1)[0]
            if v in strs: note = '   ; "%s"' % strs[v][:70]
        if L >= 5 and 0xB8 <= raw[0] <= 0xBF:
            v = struct.unpack_from('<I',raw,1)[0]
            if v in strs: note = '   ; "%s"' % strs[v][:70]
        print('  0x%06X  %-28s %s%s' % (o, ' '.join('%02X'%b for b in raw[:12]), note, mark))

# 无效属性 %d  -> attribute validity check
show_at(0x01728A, 'ATTR VALIDITY CHECK  ("无效属性 %d")', 0x200)
# 属性异常，无领悟属性 -> learn/insight attribute
show_at(0x0790C5, 'INSIGHT ATTRIBUTE  ("属性异常，无领悟属性")', 0x200)
# 选择使用的版本 -> version chooser (existing modal selection UI!)
show_at(0x0AD891, 'VERSION CHOOSER ("选择使用的版本：新人建议玩原版")', 0x300)
# 选择让[%s]遗忘以下其中一个技能 -> skill forget chooser
show_at(0x007625, 'SKILL CHOICE DIALOG ("选择让[%s]遗忘以下其中一个技能：")', 0x200)
