# -*- coding: utf-8 -*-
"""Count the four callers of the CreateCompatibleDC wrapper 0x44E710 in the
RUNNING game process (no restart).

For every call site the 5-byte `call 0x44E710` is replaced by `call thunk_i`;
thunk_i does `inc [counter_i]; jmp 0x44E710` (tail jump, stack untouched, the
wrapper's `ret 4` still returns to the original caller).
"""
import ctypes
import struct
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

WRAPPER = 0x44E710
SITES = [0x44D1E4, 0x45201C, 0x4ADA24, 0x4E66C5]
THUNK_BASE = 0x6FE380
CTR_BASE = 0x703EC0
COUNTERS = {"CreateCompatibleDC": 0x703EA0, "CreateCompatibleBitmap": 0x703EA4,
            "DeleteDC": 0x703EB4}

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_READWRITE = 0x04


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p)]


k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                       ctypes.POINTER(ctypes.c_wchar), wintypes.DWORD]
psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                       ctypes.POINTER(MODULEINFO), wintypes.DWORD]


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
                return pid, (mi.lpBaseOfDll or 0)
        k32.CloseHandle(h)
    return None


def rpm(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return None
    return buf.raw


def wpm(h, addr, data):
    buf = ctypes.create_string_buffer(data, len(data))
    got = ctypes.c_size_t()
    if not k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(got)):
        return False
    return got.value == len(data)


def protect(h, addr, size, prot):
    old = wintypes.DWORD()
    if not k32.VirtualProtectEx(h, ctypes.c_void_p(addr), size, prot, ctypes.byref(old)):
        return None
    return old.value


def main():
    r = find("probe")
    if not r:
        print("probe not running")
        return 1
    pid, base = r
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                        PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
    if not h:
        print("open failed")
        return 1
    try:
        print("pid=%d base=0x%08X" % (pid, base))
        # --- install ---
        protect(h, THUNK_BASE, 0x40, PAGE_EXECUTE_READWRITE)
        for i, site in enumerate(SITES):
            cur = rpm(h, site, 5)
            if not cur or cur[0] != 0xE8:
                print("site 0x%08X unexpected: %s" % (site, cur.hex(" ") if cur else None))
                return 1
            tgt = site + 5 + struct.unpack("<i", cur[1:])[0]
            if tgt != WRAPPER:
                print("site 0x%08X calls 0x%08X (expected wrapper)" % (site, tgt))
                return 1
            thunk_va = THUNK_BASE + i * 12
            ctr = CTR_BASE + i * 4
            thunk = (b"\xFF\x05" + struct.pack("<I", ctr) +
                     b"\xE9" + struct.pack("<i", WRAPPER - (thunk_va + 11)))
            assert len(thunk) == 11
            thunk += b"\x90"
            protect(h, thunk_va, 16, PAGE_EXECUTE_READWRITE)
            if not wpm(h, thunk_va, thunk):
                print("write thunk %d failed" % i)
                return 1
            protect(h, thunk_va, 16, PAGE_EXECUTE_READ)
            protect(h, site, 5, PAGE_EXECUTE_READWRITE)
            if not wpm(h, site, b"\xE8" + struct.pack("<i", thunk_va - (site + 5))):
                print("patch site 0x%08X failed" % site)
                return 1
            protect(h, site, 5, PAGE_EXECUTE_READ)
            print("  site 0x%08X -> thunk 0x%08X (ctr 0x%08X)" % (site, thunk_va, ctr))
        # NOTE: .wash also holds the speed caves, so it MUST keep execute
        # permission - using PAGE_READWRITE here kills the game (DEP violation
        # at 0x703E18).  Always use PAGE_EXECUTE_READWRITE for this page.
        protect(h, CTR_BASE, 16, PAGE_EXECUTE_READWRITE)
        wpm(h, CTR_BASE, b"\x00" * 16)

        # --- sample ---
        names = {"CreateCompatibleDC": 0x703EA0, "CreateCompatibleBitmap": 0x703EA4,
                 "DeleteDC": 0x703EB4}
        sites = {s: CTR_BASE + i * 4 for i, s in enumerate(SITES)}

        def snap():
            d = {}
            for n, a in names.items():
                v = rpm(h, a, 4)
                d[n] = int.from_bytes(v, "little")
            for s, a in sites.items():
                v = rpm(h, a, 4)
                d[s] = int.from_bytes(v, "little")
            return d

        a = snap()
        time.sleep(10)
        b = snap()
        print("\n%-28s %8s %8s %8s" % ("counter", "first", "last", "rate/s"))
        for k in list(names) + SITES:
            label = k if isinstance(k, str) else ("site 0x%08X" % k)
            print("%-28s %8d %8d %8.2f"
                  % (label, a[k], b[k], (b[k] - a[k]) / 10.0))
        print("\nDC calls - DeleteDC calls per second = %.2f"
              % ((b["CreateCompatibleDC"] - a["CreateCompatibleDC"] -
                  (b["DeleteDC"] - a["DeleteDC"])) / 10.0))
        return 0
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    sys.exit(main())
