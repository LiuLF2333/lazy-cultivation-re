from minidump.minidumpfile import MinidumpFile
import struct

dump = r"C:\Users\LIULF\AppData\Local\CrashDumps\懒人修仙传.exe.3528.dmp"
f = MinidumpFile.parse(dump)
mods = [(m.baseaddress, m.baseaddress + m.size, m.name) for m in f.modules.modules]


def name(v):
    for a, b, n in mods:
        if a <= v < b:
            return n.split("\\")[-1] + "+0x%x" % (v - a)
    return ""


t = f.threads.threads[0]
c = t.ContextObject
stack = None
for m in f.memory_segments.memory_segments:
    if m.start_virtual_address <= c.Esp < m.end_virtual_address:
        stack = m
        break
raw = open(f.filename, "rb").read()
base = stack.start_file_address
sp = c.Esp
print("ESP", hex(sp), "EBP", hex(c.Ebp), "EIP", hex(c.Eip))
print("stack", hex(stack.start_virtual_address), hex(stack.size))
for i in range(0, 400, 4):
    va = sp + i
    off = base + (va - stack.start_virtual_address)
    v = struct.unpack_from("<I", raw, off)[0]
    n = name(v)
    print("%08x: %08x %s" % (va, v, n))
