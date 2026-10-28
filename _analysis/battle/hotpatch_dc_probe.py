# -*- coding: utf-8 -*-
"""Hot-patch the RUNNING probe process so its CreateCompatibleDC thunk starts
recording per-call-site counters - no game restart, no save risk.

The 76 call sites already point at the 12-byte thunk at 0x6FE280, so we
  * turn that thunk into a 5-byte jump to a new thunk at 0x6FE340
  * write the counting thunk there (table at 0x704200)
  * read the table twice and print per-call-site rates
"""
import ctypes
import struct
import sys
import time
from ctypes import wintypes

sys.path.insert(0, r"D:\XiuXian\_analysis\battle")
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

THUNK_OLD = 0x6FE280
THUNK_NEW = 0x6FE340
TABLE_VA = 0x704200
TABLE_N = 256
CNT_VA = 0x703EA0          # probe1's CreateCompatibleDC counter
IAT = 0x6451AC             # CreateCompatibleDC
OLD_THUNK_BYTES = bytes.fromhex("ff05a03e7000" "ff25ac516400")

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
                return pid, (mi.lpBaseOfDll or 0), b.value
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


def build_thunk():
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    src = """
        push eax
        push edx
        mov  eax, dword ptr [esp + 8]
        mov  edx, eax
        shr  edx, 4
        and  edx, %d
        shl  edx, 3
        add  edx, %d
        cmp  dword ptr [edx], eax
        je   hit
        mov  dword ptr [edx], eax
        mov  dword ptr [edx + 4], 0
    hit:
        inc  dword ptr [edx + 4]
        inc  dword ptr [%d]
        pop  edx
        pop  eax
        jmp  dword ptr [%d]
    """ % (TABLE_N - 1, TABLE_VA, CNT_VA, IAT)
    enc, _ = ks.asm(src, addr=THUNK_NEW)
    return bytes(enc)


def main():
    r = find("probe")
    if not r:
        print("probe process not running")
        return 1
    pid, base, path = r
    print("pid=%d base=0x%08X %s" % (pid, base, path))
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                        PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
    if not h:
        print("OpenProcess(write) failed: %d" % ctypes.get_last_error())
        return 1
    try:
        # 1. sanity: is the counter table area committed?
        if rpm(h, TABLE_VA, TABLE_N * 8) is None:
            print("table area 0x%08X not readable -> abort (use probe2.exe instead)" % TABLE_VA)
            return 1
        if rpm(h, THUNK_NEW, 64) is None:
            print("thunk area not readable -> abort")
            return 1
        cur = rpm(h, THUNK_OLD, 12)
        if cur != OLD_THUNK_BYTES:
            print("unexpected thunk content %s -> abort" % (cur.hex(" ") if cur else None))
            return 1

        thunk = build_thunk()
        stub = b"\xE9" + struct.pack("<i", THUNK_NEW - (THUNK_OLD + 5)) + b"\x90" * 7
        assert len(stub) == 12

        if protect(h, THUNK_NEW, 64, PAGE_EXECUTE_READWRITE) is None:
            print("VirtualProtectEx(thunk) failed: %d" % ctypes.get_last_error())
            return 1
        if not wpm(h, THUNK_NEW, thunk):
            print("write thunk failed")
            return 1
        protect(h, THUNK_NEW, 64, PAGE_EXECUTE_READ)

        if protect(h, THUNK_OLD, 12, PAGE_EXECUTE_READWRITE) is None:
            print("VirtualProtectEx(stub) failed")
            return 1
        if not wpm(h, THUNK_OLD, stub):
            print("write stub failed")
            return 1
        protect(h, THUNK_OLD, 12, PAGE_EXECUTE_READ)

        # zero the table
        if protect(h, TABLE_VA, TABLE_N * 8, PAGE_READWRITE) is None:
            print("VirtualProtectEx(table) failed: %d" % ctypes.get_last_error())
            return 1
        wpm(h, TABLE_VA, b"\x00" * (TABLE_N * 8))
        print("hot patch installed: %d byte thunk at 0x%08X, table at 0x%08X"
              % (len(thunk), THUNK_NEW, TABLE_VA))

        def sample():
            raw = rpm(h, TABLE_VA, TABLE_N * 8)
            tot = rpm(h, CNT_VA, 4)
            d = {}
            for k in range(TABLE_N):
                ret = int.from_bytes(raw[k * 8:k * 8 + 4], "little")
                c = int.from_bytes(raw[k * 8 + 4:k * 8 + 8], "little")
                if ret and c:
                    d[ret] = d.get(ret, 0) + c
            return d, int.from_bytes(tot, "little")

        a, ca = sample()
        time.sleep(10)
        b, cb = sample()
        print("total calls: %d -> %d  (+%d in 10 s)" % (ca, cb, cb - ca))
        print("\n%-10s %-8s %-12s %s" % ("calls", "rate/s", "call site", "ret addr"))
        for ret, c in sorted(b.items(), key=lambda kv: -kv[1])[:20]:
            print("%-10d %-8.2f 0x%08X   0x%08X"
                  % (c, (c - a.get(ret, 0)) / 10.0, ret - 5, ret))
        return 0
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    sys.exit(main())
