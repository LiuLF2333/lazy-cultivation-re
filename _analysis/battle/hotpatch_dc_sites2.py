# -*- coding: utf-8 -*-
"""Hot-patch the RUNNING probe3 process: turn the CreateCompatibleDC thunk into
a per-call-site counter, then print per-site rates.

Safety rules (learned the hard way):
  * NEVER change the protection of .wash (0x703000-0x704000): the speed caves
    live there and need PAGE_EXECUTE_READWRITE.  We do not touch it at all.
  * thunks live in .atrsel (executable): PAGE_EXECUTE_READWRITE -> write ->
    restore PAGE_EXECUTE_READ.
  * the counter table lives in .washd (0x704000+, not executable):
    PAGE_READWRITE is fine there.
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

DC_THUNK = 0x6FE280          # probe3: 12-byte thunk for CreateCompatibleDC
THUNK_NEW = 0x6FE380         # free tail of .atrsel
TABLE_VA = 0x704200          # .washd page (RW)
TABLE_N = 256
CNT_VA = 0x703EA0            # probe3's CreateCompatibleDC counter
IAT = 0x6451AC
DC_THUNK_BYTES = bytes.fromhex("ff05a03e7000" "ff25ac516400")

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
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_size_t]
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
    return k32.VirtualProtectEx(h, ctypes.c_void_p(addr), size, prot, ctypes.byref(old))


def main():
    r = find("probe3")
    if not r:
        print("probe3 not running")
        return 1
    pid, base = r
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                        PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
    if not h:
        print("open failed: %d" % ctypes.get_last_error())
        return 1
    try:
        print("pid=%d base=0x%08X" % (pid, base))
        cur = rpm(h, DC_THUNK, 12)
        if cur != DC_THUNK_BYTES:
            print("dc thunk unexpected: %s" % (cur.hex(" ") if cur else None))
            return 1
        if rpm(h, THUNK_NEW, 64) is None or rpm(h, TABLE_VA, TABLE_N * 8) is None:
            print("thunk/table area not readable -> abort")
            return 1

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
        thunk, _ = ks.asm(src, addr=THUNK_NEW)
        thunk = bytes(thunk)

        if not protect(h, THUNK_NEW, 64, PAGE_EXECUTE_READWRITE):
            print("protect thunk failed")
            return 1
        if not wpm(h, THUNK_NEW, thunk):
            print("write thunk failed")
            return 1
        protect(h, THUNK_NEW, 64, PAGE_EXECUTE_READ)

        stub = b"\xE9" + struct.pack("<i", THUNK_NEW - (DC_THUNK + 5)) + b"\x90" * 7
        if not protect(h, DC_THUNK, 16, PAGE_EXECUTE_READWRITE):
            print("protect stub failed")
            return 1
        if not wpm(h, DC_THUNK, stub):
            print("write stub failed")
            return 1
        protect(h, DC_THUNK, 16, PAGE_EXECUTE_READ)

        if not protect(h, TABLE_VA, TABLE_N * 8, PAGE_READWRITE):
            print("protect table failed")
            return 1
        wpm(h, TABLE_VA, b"\x00" * (TABLE_N * 8))
        print("per-site counting installed (thunk 0x%08X, table 0x%08X)"
              % (THUNK_NEW, TABLE_VA))

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
        print("total DC calls: %d -> %d (+%d in 10 s)" % (ca, cb, cb - ca))
        print("\n%-8s %-8s %s" % ("calls", "rate/s", "call site"))
        for ret, c in sorted(b.items(), key=lambda kv: -kv[1])[:20]:
            print("%-8d %-8.2f 0x%08X" % (c, (c - a.get(ret, 0)) / 10.0, ret - 5))
        return 0
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    sys.exit(main())
