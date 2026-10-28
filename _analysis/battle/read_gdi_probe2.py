# -*- coding: utf-8 -*-
"""Dump the per-call-site CreateCompatibleDC counters of probe2.

    python read_gdi_probe2.py            # snapshot + rates (2 samples 10 s apart)
"""
import ctypes
import sys
import time
from ctypes import wintypes

psapi = ctypes.WinDLL("psapi", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)

BASE_VA = 0x400000
TABLE_VA = 0x704200
TABLE_N = 256
CNT_VA = 0x7041F4

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


def sample(h, off):
    tbl = read_block(h, TABLE_VA + off, TABLE_N * 8)
    cnt = read_block(h, CNT_VA + off, 4)
    if not tbl or not cnt:
        return None, None
    d = {}
    for k in range(TABLE_N):
        ret = int.from_bytes(tbl[k * 8:k * 8 + 4], "little")
        c = int.from_bytes(tbl[k * 8 + 4:k * 8 + 8], "little")
        if ret and c:
            d[ret] = d.get(ret, 0) + c
    return d, int.from_bytes(cnt, "little")


def main():
    r = find("probe2")
    if not r:
        print("probe2 not running")
        return
    pid, h, base, path = r
    off = base - BASE_VA
    print("pid=%d base=0x%08X %s" % (pid, base, path))
    a, ca = sample(h, off)
    time.sleep(10)
    b, cb = sample(h, off)
    k32.CloseHandle(h)
    if a is None or b is None:
        print("read failed")
        return
    print("total CreateCompatibleDC calls: %d -> %d  (+%d in 10 s)"
          % (ca, cb, cb - ca))
    print("\n%-10s %-7s %-12s %s" % ("calls", "rate/s", "call site", "ret addr"))
    for ret, c in sorted(b.items(), key=lambda kv: -kv[1])[:20]:
        rate = (c - a.get(ret, 0)) / 10.0
        print("%-10d %-7.2f 0x%08X   0x%08X" % (c, rate, ret - 5, ret))


if __name__ == "__main__":
    main()
