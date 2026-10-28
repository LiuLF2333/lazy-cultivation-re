# -*- coding: utf-8 -*-
"""Execute the injected chooser machine code OUTSIDE the game, with the Win32
entry points it calls replaced by instrumented Python callbacks.

This exercises the real patched bytes (position independence, frame layout,
argument marshalling, return-value contract) deterministically and without
popping a menu on screen.

Layout: one RWX region of 0x250000 bytes is the fake "module image".
  image + 0x24462A  the injected code (copied verbatim from the patched EXE)
  image + 0x1A120   stub for the original RNG (0x41A120) used by the fallback
  image + 0x2457xx  the fake IAT slots the code reaches via [ebx + rva]

Getting image+0x1A120 and image+0x2457xx inside the same allocation proves the
rel32 tail-jump and the [ebx+rva] IAT reach both work on a *relocated* image —
exactly the situation in the running game (observed load base 0xA0000).
"""
import ctypes
import io
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE

OUT = r"D:\XiuXian\_analysis\reports\harness.txt"
f = io.StringIO()

PATCHED = r"D:\XiuXian\懒人修仙传.exe"
CAVE_VA = 0x64462A
CODE_LEN = 0x11E            # code bytes before the strings

IAT_RVA = {
    "CreatePopupMenu": 0x245728, "AppendMenuW": 0x245724,
    "GetCursorPos": 0x2457F0, "GetForegroundWindow": 0x245600,
    "GetActiveWindow": 0x2456D8, "SetForegroundWindow": 0x2455FC,
    "TrackPopupMenu": 0x245608, "DestroyMenu": 0x24556C,
}
RNG_RVA = 0x1A120

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                             ctypes.c_ulong, ctypes.c_ulong]
MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE = 0x3000, 0x40

IMG_SIZE = 0x250000
img = k32.VirtualAlloc(None, IMG_SIZE, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
if not img:
    raise SystemExit("VirtualAlloc failed")
f.write("### fake image allocated at 0x%X (relocated, like the running game)\n" % img)

# copy the injected code verbatim out of the patched EXE
pe = PE(PATCHED)
code = pe.raw[pe.va2off(CAVE_VA):pe.va2off(CAVE_VA) + CODE_LEN]
ctypes.memmove(img + (CAVE_VA - IMAGE_BASE), code, CODE_LEN)
f.write("  code copied: %d bytes -> 0x%X\n" % (len(code), img + (CAVE_VA - IMAGE_BASE)))

# --- fallback RNG stub: mov eax, 0x2A ; ret   (sentinel 42 = "fallback used")
rng_stub = b"\xB8" + struct.pack("<I", 42) + b"\xC3"
ctypes.memmove(img + RNG_RVA, rng_stub, len(rng_stub))

# --- instrumented Win32 callbacks
CALLS = []
CUR = {"x": 111, "y": 222}


def _ret(name, val):
    def fn(*a):
        CALLS.append((name, a))
        return val
    return fn


cb_create = ctypes.CFUNCTYPE(ctypes.c_int)(_ret("CreatePopupMenu", 1))
cb_append = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                             ctypes.c_void_p, ctypes.c_wchar_p)(_ret("AppendMenuW", 1))
cb_fg = ctypes.CFUNCTYPE(ctypes.c_void_p)(_ret("GetForegroundWindow", 0x1234))
cb_setfg = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(_ret("SetForegroundWindow", 1))
cb_destroy = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(_ret("DestroyMenu", 1))

TPM_RESULT = {"v": 3}
CB_TRACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_void_p, ctypes.c_void_p)


@CB_TRACK
def cb_track(hmenu, flags, x, y, reserved, hwnd, rect):
    CALLS.append(("TrackPopupMenu", (hmenu, hex(flags), x, y, reserved, hwnd, rect)))
    return TPM_RESULT["v"]


CB_GCP = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_long))


@CB_GCP
def cb_getcursor(pt):
    CALLS.append(("GetCursorPos", (bool(pt),)))
    pt[0] = CUR["x"]
    pt[1] = CUR["y"]
    return 1


CB_ACT = ctypes.CFUNCTYPE(ctypes.c_void_p)


@CB_ACT
def cb_active():
    CALLS.append(("GetActiveWindow", ()))
    return 0


SLOTS = {"CreatePopupMenu": cb_create, "AppendMenuW": cb_append,
         "GetForegroundWindow": cb_fg, "GetActiveWindow": cb_active,
         "SetForegroundWindow": cb_setfg, "TrackPopupMenu": cb_track,
         "DestroyMenu": cb_destroy, "GetCursorPos": cb_getcursor}
for name, rva in IAT_RVA.items():
    ptr = ctypes.cast(SLOTS[name], ctypes.c_void_p).value
    ctypes.memmove(img + rva, struct.pack("<I", ptr), 4)
f.write("  fake IAT populated (%d slots)\n" % len(IAT_RVA))

CHOOSER = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int)(
    img + (CAVE_VA - IMAGE_BASE))
weights = (ctypes.c_int * 6)(100, 100, 100, 100, 100, 10)


def run(sel, label):
    CALLS.clear()
    TPM_RESULT["v"] = sel
    r = CHOOSER(ctypes.cast(weights, ctypes.c_void_p), 6)
    names = [c[0] for c in CALLS]
    return r, names


f.write("\n### selection -> returned attr index (caller does +1 => attr id 1..6)\n")
ok = True
expected = {1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}
for sel, exp in expected.items():
    r, names = run(sel, "sel%d" % sel)
    good = (r == exp)
    ok &= good
    f.write("  menu cmd %d -> eax %d (expect %d) %s\n"
            % (sel, r, exp, "OK" if good else "FAIL"))

f.write("\n### cancel / invalid -> fallback to the ORIGINAL random (sentinel 42)\n")
for sel in (0, 7, 100, -1):
    r, names = run(sel, "sel%d" % sel)
    good = (r == 42)
    ok &= good
    f.write("  menu cmd %d -> eax %d (expect 42 fallback) %s\n"
            % (sel, r, "OK" if good else "FAIL"))

f.write("\n### call sequence and argument correctness (selection = 3 -> 武术)\n")
CALLS.clear()
TPM_RESULT["v"] = 3
r = CHOOSER(ctypes.cast(weights, ctypes.c_void_p), 6)
for name, args in CALLS:
    f.write("  %-22s %s\n" % (name, args))
f.write("  returned %d (expect 2)\n" % r)
ok &= (r == 2)

# verify the AppendMenuW payloads are the six attribute names in order
labels = [a[1] for n, a in CALLS if n == "AppendMenuW"]
f.write("\n### menu entry labels passed to AppendMenuW: %s\n" % labels)
ok &= (labels == ["\u6839\u9aa8", "\u771f\u6c14", "\u6b66\u672f",
                  "\u7075\u529b", "\u7075\u5de7", "\u673a\u7f18"])
# uIDNewItem must be 1..6
ids = [a[0] for n, a in CALLS if n == "AppendMenuW"]
f.write("### menu entry ids: %s\n" % ids)
ok &= (ids == [1, 2, 3, 4, 5, 6])

# argument order / values of TrackPopupMenu
tp = [a for n, a in CALLS if n == "TrackPopupMenu"][0]
f.write("\n### TrackPopupMenu args: flags=%s x=%s y=%s reserved=%s hwnd=%s rect=%s\n"
        % (tp[1], tp[2], tp[3], tp[4], tp[5], tp[6]))
ok &= (tp[1] == "0x100")                 # TPM_RETURNCMD
ok &= (tp[2] == CUR["x"] and tp[3] == CUR["y"])   # POINT passed through correctly
ok &= (tp[5] == 0x1234)                  # hwnd propagated
ok &= (tp[6] is None)                    # prcRect = NULL

# DestroyMenu must be called with the same hmenu as TrackPopupMenu
hm_track, hm_destroy = tp[0], [a[0] for n, a in CALLS if n == "DestroyMenu"][0]
f.write("### hmenu TrackPopupMenu=0x%X DestroyMenu=0x%X match=%s\n"
        % (hm_track, hm_destroy, hm_track == hm_destroy))
ok &= (hm_track == hm_destroy)

# ebx/esi/edi/ebp preservation: ctypes would likely crash or misbehave otherwise,
# but assert explicitly that repeated calls are stable
rs = [run(s, "")[0] for s in (1, 2, 3, 4, 5, 6, 0)]
f.write("\n### repeated-call stability (register preservation): %s\n" % rs)
ok &= (rs == [0, 1, 2, 3, 4, 5, 42])

# GetForegroundWindow returning 0 must fall back to GetActiveWindow
f.write("\n### NULL foreground window -> GetActiveWindow fallback\n")
CALLS.clear()
cb_fg2 = ctypes.CFUNCTYPE(ctypes.c_void_p)(_ret("GetForegroundWindow", 0))
cb_ac2 = ctypes.CFUNCTYPE(ctypes.c_void_p)(_ret("GetActiveWindow", 0xABCD))
ctypes.memmove(img + IAT_RVA["GetForegroundWindow"],
               struct.pack("<I", ctypes.cast(cb_fg2, ctypes.c_void_p).value), 4)
ctypes.memmove(img + IAT_RVA["GetActiveWindow"],
               struct.pack("<I", ctypes.cast(cb_ac2, ctypes.c_void_p).value), 4)
TPM_RESULT["v"] = 5
r = CHOOSER(ctypes.cast(weights, ctypes.c_void_p), 6)
f.write("  calls: %s -> eax %d (expect 4)\n" % ([c[0] for c in CALLS], r))
ok &= (r == 4)
tp2 = [a for n, a in CALLS if n == "TrackPopupMenu"]
ok &= bool(tp2) and tp2[0][5] == 0xABCD
f.write("  hwnd used by TrackPopupMenu = 0x%X (expect 0xABCD)\n"
        % (tp2[0][5] if tp2 else -1))

f.write("\n### RESULT: %s\n" % ("ALL CHECKS PASSED" if ok else "FAILURES PRESENT"))
open(OUT, "w", encoding="utf-8").write(f.getvalue())
print("harness done, ok=%s" % ok)
