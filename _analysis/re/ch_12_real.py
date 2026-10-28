# -*- coding: utf-8 -*-
"""Find the REAL dialog / list-selection mechanism."""
import sys, struct
sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, disasm, fmt, IMAGE_BASE

OUT = open(r"D:\XiuXian\_analysis\re\out\ch_12_real.txt", "w", encoding="utf-8")
def P(*a): OUT.write(" ".join(str(x) for x in a) + "\n")
pe = PE(); raw = pe.raw

# ---------- IAT lookup ----------
def rva2off(rva):
    for s in pe.sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + (rva - s["va"])
    return None
imp_rva, imp_sz = struct.unpack_from("<II", raw, pe.opt + 96 + 8)
iat = {}
o = rva2off(imp_rva); i = 0
while True:
    oft, ts, fc, namerva, firstthunk = struct.unpack_from("<IIIII", raw, o + i*20)
    if namerva == 0 and firstthunk == 0: break
    noff = rva2off(namerva); dll = raw[noff:raw.index(b"\0", noff)].decode("latin1")
    toff = rva2off(oft) if oft else rva2off(firstthunk)
    j = 0
    while True:
        v = struct.unpack_from("<I", raw, toff + j*4)[0]
        if v == 0: break
        nm = "ORD_%d" % (v & 0xFFFF) if (v & 0x80000000) else \
             raw[rva2off(v)+2:raw.index(b"\0", rva2off(v)+2)].decode("latin1")
        iat[IMAGE_BASE + firstthunk + j*4] = (dll, nm); j += 1
    i += 1
if name := None: pass
name2va = {}
for va, (dll, nm) in iat.items():
    name2va.setdefault(nm, []).append(va)

P("#" * 100)
P("DIALOG-RELATED IMPORTS AND THEIR IAT VAs")
P("#" * 100)
WANT = ["EndDialog", "CreateDialogIndirectParamW", "CreateDialogIndirectParamAorW",
        "DialogBoxParamW", "DialogBoxIndirectParamW", "MessageBoxW", "MessageBoxA",
        "SetWindowTextW", "GetDlgItemTextW", "SendDlgItemMessageW", "GetDlgItem",
        "GetWindowTextW", "CheckDlgButton", "GetDlgCtrlID", "CreateWindowExW",
        "GetCursorPos", "ShowWindow", "GetWindowRect", "SetFocus", "SetCapture",
        "GetKeyState", "GetAsyncKeyState", "PeekMessageW", "TranslateMessage",
        "DispatchMessageW", "InvalidateRect", "UpdateWindow", "BitBlt",
        "GetMessageW", "PostQuitMessage", "wsprintfW", "DialogBoxIndirectParamA"]
for w in WANT:
    P("  %-28s %s" % (w, ", ".join("0x%X" % v for v in name2va.get(w, [])) or "-"))

# find a way to call-through-IAT: FF15 <IAT VA>
TRP, TVA, TRS = pe.text()
text = raw[TRP:TRP+TRS]
def find_ff15(iat_va):
    b = struct.pack("<I", iat_va)
    hits = []
    st = 0
    while True:
        i = text.find(b"\xff\x15" + b, st)
        if i < 0: break
        hits.append(IMAGE_BASE + TVA + i)
        st = i + 1
    return hits

P("")
P("#" * 100)
P("CALL SITES of dialog-related IAT slots")
P("#" * 100)
for w in WANT:
    for va in name2va.get(w, []):
        h = find_ff15(va)
        if h:
            P("  %-28s IAT 0x%X : %d sites -> %s" % (w, va, len(h), ", ".join("0x%X" % x for x in h[:20])))

# ---------- strings near the attr domain ----------
P("")
P("#" * 100)
P("LITERAL STRINGS used at the known chooser-ish sites")
P("#" * 100)
for va in (0x68E974, 0x68E998, 0x68E98C, 0x68E9AC, 0x68E9CC, 0x68E960, 0x68E9E0, 0x68E9F0):
    P("  0x%08X : %r" % (va, pe.wide(va)))

# ---------- search for the 6 attribute names ----------
P("")
P("#" * 100)
P("SEARCH: attribute-name clusters (UTF-16) in .rdata/.data")
P("#" * 100)
CAND = ["根骨", "悟性", "灵根", "神识", "力量", "敏捷", "体质", "气血", "法力", "攻击", "防御", "暴击", "运气", "资质", "属性"]
for c in CAND:
    b = c.encode("utf-16-le")
    st = 0; hits = []
    while True:
        i = raw.find(b, st)
        if i < 0: break
        va = pe.off2va(i)
        if va: hits.append(va)
        st = i + 1
    P("  %-6s %d hits: %s" % (c, len(hits), ", ".join("0x%X" % h for h in hits[:12])))

P("")
P("#" * 100)
P("SEARCH: the phrase 属性 (0x5C5E 0x6027) context")
P("#" * 100)
b = "属性".encode("utf-16-le")
st = 0
while True:
    i = raw.find(b, st)
    if i < 0: break
    va = pe.off2va(i)
    if va:
        # rewind to string start
        j = i
        while j - 2 > 0 and (raw[j-2] | (raw[j-1] << 8)) != 0:
            j -= 2
        P("  0x%08X : %r" % (pe.off2va(j), pe.wide(pe.off2va(j))))
    st = i + 1
OUT.close()
print("ok")
