# -*- coding: utf-8 -*-
"""Read the counters of 懒人修仙传.probe3.exe from outside the process.

    python read_gdi_probe.py --match probe3            # snapshot + rates
    python read_gdi_probe.py --match probe3 --csv f.csv --watch 300
"""
import ctypes
import sys
import time
from ctypes import wintypes

psapi = ctypes.WinDLL("psapi", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)

BASE_VA = 0x400000
COUNTER_VA = 0x703EA0
NAMES = [
    "CreateCompatibleDC", "CreateCompatibleBitmap", "CreateBitmap",
    "CreateDIBitmap", "CreateSolidBrush", "CreateHatchBrush",
    "CreatePatternBrush", "CreatePen", "CreateFontIndirectW", "CreateFontW",
    "CreatePalette", "LoadBitmapW", "DeleteObject", "DeleteDC", "DestroyIcon",
]
SITE_VA = 0x703EE0
SITE_NAMES = ["caller 0x44D1E4", "caller 0x45201C", "caller 0x4ADA24", "caller 0x4E66C5"]

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p)]


k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
psapi.EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                       ctypes.POINTER(ctypes.c_wchar), wintypes.DWORD]
psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                       ctypes.POINTER(MODULEINFO), wintypes.DWORD]


def read_block(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return None
    return buf.raw


def find(substr):
    pids = (wintypes.DWORD * 4096)()
    need = wintypes.DWORD()
    psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(need))
    for i in range(need.value // 4):
        pid = pids[i]
        if not pid:
            continue
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        mods = (wintypes.HMODULE * 64)()
        n2 = wintypes.DWORD()
        if psapi.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(n2)):
            b = ctypes.create_unicode_buffer(260)
            psapi.GetModuleFileNameExW(h, mods[0], b, 260)
            if substr.lower() in b.value.lower():
                mi = MODULEINFO()
                psapi.GetModuleInformation(h, mods[0], ctypes.byref(mi), ctypes.sizeof(mi))
                return pid, h, (mi.lpBaseOfDll or 0), b.value
        k32.CloseHandle(h)
    return None


def snapshot(substr):
    r = find(substr)
    if not r:
        return None
    pid, h, base, path = r
    off = base - BASE_VA
    raw = read_block(h, COUNTER_VA + off, 4 * len(NAMES))
    site = read_block(h, SITE_VA + off, 4 * len(SITE_NAMES))
    k32.CloseHandle(h)
    if raw is None or site is None:
        return None
    vals = [int.from_bytes(raw[k * 4:k * 4 + 4], "little") for k in range(len(NAMES))]
    svals = [int.from_bytes(site[k * 4:k * 4 + 4], "little") for k in range(len(SITE_NAMES))]
    return pid, base, path, vals, svals


def main():
    match = "probe3"
    if "--match" in sys.argv:
        match = sys.argv[sys.argv.index("--match") + 1]
    watch = 0
    if "--watch" in sys.argv:
        watch = int(sys.argv[sys.argv.index("--watch") + 1])
    csv = None
    if "--csv" in sys.argv:
        csv = sys.argv[sys.argv.index("--csv") + 1]
        with open(csv, "w", encoding="utf-8") as f:
            f.write("ts," + ",".join(NAMES + SITE_NAMES) + "\n")
    prev = None
    t0 = time.time()
    while True:
        s = snapshot(match)
        if not s:
            print("process not running (match=%r)" % match)
        else:
            pid, base, path, vals, svals = s
            if csv:
                with open(csv, "a", encoding="utf-8") as f:
                    f.write(time.strftime("%H:%M:%S") + "," +
                            ",".join(str(v) for v in vals + svals) + "\n")
                print(time.strftime("%H:%M:%S"), "base=0x%08X" % base,
                      "DC=%d BM=%d DelDC=%d" % (vals[0], vals[1], vals[13]),
                      "sites=%s" % (svals,))
            else:
                print("%s  pid=%d base=0x%08X" % (time.strftime("%H:%M:%S"), pid, base))
                for n, v in list(zip(NAMES, vals)) + list(zip(SITE_NAMES, svals)):
                    d = "" if prev is None else ("   +%d" % (v - prev[n]))
                    print("  %-24s %8d%s" % (n, v, d))
            prev = dict(zip(NAMES + SITE_NAMES, vals + svals))
        if not watch or time.time() - t0 > watch:
            break
        if not csv:
            print("-" * 44)
        time.sleep(5)


if __name__ == "__main__":
    main()
