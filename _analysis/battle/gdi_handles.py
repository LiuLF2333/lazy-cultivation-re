# -*- coding: utf-8 -*-
"""Read a process' GDI shared handle table (PEB->GdiSharedHandleTable) and
count live GDI objects by type.

Usage:
    python gdi_handles.py --self          # calibrate: create known objects
    python gdi_handles.py --pid 3660      # count objects of that process
"""
import ctypes
import sys
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]


def open_proc(pid):
    h = k32.OpenProcess(0x0410 | 0x0010, False, pid)  # QUERY_INFO|VM_READ|VM_WRITE?no
    if not h:
        h = k32.OpenProcess(0x0410, False, pid)       # QUERY_INFORMATION | VM_READ
    if not h:
        raise OSError("OpenProcess failed: %d" % ctypes.get_last_error())
    return h


def peb_of(pid, h=None):
    h = h or open_proc(pid)
    pbi = PROCESS_BASIC_INFORMATION()
    ret = ctypes.c_ulong()
    status = ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi),
                                             ctypes.sizeof(pbi), ctypes.byref(ret))
    if status != 0:
        raise OSError("NtQueryInformationProcess -> 0x%08X" % (status & 0xFFFFFFFF))
    return pbi.PebBaseAddress, h


def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    if not ok:
        return None
    return buf.raw


def gdi_table(pid):
    peb, h = peb_of(pid)
    raw = read_mem(h, peb + 0x94, 4)          # x86 PEB->GdiSharedHandleTable
    if not raw:
        raise OSError("cannot read PEB->GdiSharedHandleTable")
    table = int.from_bytes(raw, "little")
    return table, h


def entry_size_and_offsets(table, h, mypid):
    """Guess the entry stride by looking for our pid in the table."""
    for stride in (0x10, 0x18, 0x14):
        blob = read_mem(h, table, stride * 0x1000)
        if not blob:
            continue
        ok = 0
        for idx in range(0x1000):
            e = blob[idx * stride: idx * stride + stride]
            pid = int.from_bytes(e[4:6], "little")
            if pid == (mypid & 0xFFFF):
                ok += 1
        if ok:
            return stride, ok
    return None, 0


def self_calibration():
    pid = k32.GetCurrentProcessId()
    # create one object of each kind and remember the handle index
    hdc_screen = user32.GetDC(0)
    hdc = gdi32.CreateCompatibleDC(hdc_screen)
    hbm = gdi32.CreateCompatibleBitmap(hdc_screen, 8, 8)
    hfont = gdi32.CreateFontW(12, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 0, 0, "Arial")
    hbrush = gdi32.CreateSolidBrush(0x00112233)
    hpen = gdi32.CreatePen(0, 1, 0x00445566)
    hpal = gdi32.CreatePalette(None)
    hregion = gdi32.CreateRectRgn(0, 0, 4, 4)
    objs = dict(DC=hdc, Bitmap=hbm, Font=hfont, Brush=hbrush, Pen=hpen,
                Palette=hpal, Region=hregion)

    table, h = gdi_table(pid)
    print("self pid=%d peb_table=0x%08X" % (pid, table))
    stride, hits = entry_size_and_offsets(table, h, pid)
    print("entry stride guess = 0x%X (%d entries with our pid)" % (stride or 0, hits))
    if not stride:
        return
    blob = read_mem(h, table, stride * 0x10000)
    print("table readable: %d bytes" % (len(blob) if blob else 0))
    for name, hv in objs.items():
        idx = hv & 0xFFFF
        e = blob[idx * stride: idx * stride + stride]
        print("  %-8s handle=%08X idx=%5d  type=%d  pid=%d  count=%d" % (
            name, hv, idx, int.from_bytes(e[0xA:0xC], "little"),
            int.from_bytes(e[4:6], "little"), int.from_bytes(e[6:8], "little")))
    user32.ReleaseDC(0, hdc_screen)


def count_by_type(pid):
    table, h = gdi_table(pid)
    stride, _ = entry_size_and_offsets(table, h, pid)
    if not stride:
        print("stride unknown")
        return
    blob = read_mem(h, table, stride * 0x10000)
    if not blob:
        print("read failed")
        return
    counts = {}
    for idx in range(0x10000):
        e = blob[idx * stride: idx * stride + stride]
        if int.from_bytes(e[4:6], "little") != (pid & 0xFFFF):
            continue
        if int.from_bytes(e[6:8], "little") == 0:   # wCount==0 -> free slot
            continue
        t = int.from_bytes(e[0xA:0xC], "little")
        counts[t] = counts.get(t, 0) + 1
    print("pid=%d table=0x%08X stride=0x%X total=%d" % (pid, table, stride, sum(counts.values())))
    for t, c in sorted(counts.items()):
        print("  type %2d : %d" % (t, c))


if __name__ == "__main__":
    if "--self" in sys.argv:
        self_calibration()
    else:
        i = sys.argv.index("--pid")
        count_by_type(int(sys.argv[i + 1]))
