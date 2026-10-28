import struct, sys, math, os

PATH = r"D:\XiuXian\懒人修仙传.exe"

def entropy(b):
    if not b: return 0.0
    from collections import Counter
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

class PE:
    def __init__(self, path):
        self.path = path
        with open(path,'rb') as f: self.data = f.read()
        d = self.data
        assert d[:2] == b'MZ', 'no MZ'
        self.e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
        assert d[self.e_lfanew:self.e_lfanew+4] == b'PE\0\0', 'no PE sig'
        coff = self.e_lfanew + 4
        (self.machine, self.nsec, self.tstamp, self.psym, self.nsym,
         self.opt_size, self.characteristics) = struct.unpack_from('<HHIIIHH', d, coff)
        self.opt_off = coff + 20
        o = self.opt_off
        self.magic = struct.unpack_from('<H', d, o)[0]
        if self.magic == 0x10b:
            self.pe32 = True
            self.image_base = struct.unpack_from('<I', d, o+28)[0]
            self.section_align = struct.unpack_from('<I', d, o+32)[0]
            self.file_align = struct.unpack_from('<I', d, o+36)[0]
            self.size_image = struct.unpack_from('<I', d, o+56)[0]
            self.subsystem = struct.unpack_from('<H', d, o+68)[0]
            self.dllchar = struct.unpack_from('<H', d, o+70)[0]
            self.ndd = struct.unpack_from('<I', d, o+92)[0]
            self.dd_off = o + 96
        elif self.magic == 0x20b:
            self.pe32 = False
            self.image_base = struct.unpack_from('<Q', d, o+24)[0]
            self.section_align = struct.unpack_from('<I', d, o+32)[0]
            self.file_align = struct.unpack_from('<I', d, o+36)[0]
            self.size_image = struct.unpack_from('<I', d, o+56)[0]
            self.subsystem = struct.unpack_from('<H', d, o+68)[0]
            self.dllchar = struct.unpack_from('<H', d, o+70)[0]
            self.ndd = struct.unpack_from('<I', d, o+108)[0]
            self.dd_off = o + 112
        else:
            raise Exception('bad magic %x' % self.magic)
        self.dd = []
        for i in range(min(self.ndd,16)):
            rva, sz = struct.unpack_from('<II', d, self.dd_off + i*8)
            self.dd.append((rva,sz))
        self.sections = []
        s = self.opt_off + self.opt_size
        for i in range(self.nsec):
            name = d[s:s+8].rstrip(b'\0')
            vsz, vaddr, rawsz, rawptr = struct.unpack_from('<IIII', d, s+8)
            chars = struct.unpack_from('<I', d, s+36)[0]
            self.sections.append(dict(name=name.decode('latin1'), vsize=vsz, vaddr=vaddr,
                rawsize=rawsz, rawptr=rawptr, chars=chars))
            s += 40
        self.entry = struct.unpack_from('<I', d, o+16)[0]
        self.checksum = struct.unpack_from('<I', d, o+64)[0]

    def rva2off(self, rva):
        for sec in self.sections:
            if sec['vaddr'] <= rva < sec['vaddr'] + max(sec['vsize'], sec['rawsize']):
                return sec['rawptr'] + (rva - sec['vaddr'])
        return None

    def off2rva(self, off):
        for sec in self.sections:
            if sec['rawptr'] <= off < sec['rawptr'] + sec['rawsize']:
                return sec['vaddr'] + (off - sec['rawptr'])
        return None

    def dir(self, idx, name):
        rva,sz = self.dd[idx]
        return dict(name=name, rva=rva, size=sz, off=self.rva2off(rva) if rva else None)

if __name__ == '__main__':
    p = PE(PATH)
    print('File      :', p.path, len(p.data), 'bytes')
    print('e_lfanew  : 0x%X' % p.e_lfanew)
    print('Machine   : 0x%04X %s' % (p.machine, {0x14c:'i386',0x8664:'amd64'}.get(p.machine,'?')))
    print('Sections  : %d' % p.nsec)
    print('Timestamp : %d  %s' % (p.tstamp, __import__('datetime').datetime.utcfromtimestamp(p.tstamp)))
    print('Magic     : 0x%X (PE32=%s)' % (p.magic, p.pe32))
    print('ImageBase : 0x%X' % p.image_base)
    print('EntryRVA  : 0x%X' % p.entry)
    print('Subsystem : %d   DllChar: 0x%X' % (p.subsystem, p.dllchar))
    print('SectAlign : 0x%X  FileAlign: 0x%X' % (p.section_align, p.file_align))
    print('SizeImage : 0x%X' % p.size_image)
    print('Checksum  : 0x%X' % p.checksum)
    print()
    print('%-10s %10s %10s %10s %10s %10s %8s' % ('Name','VirtAddr','VirtSize','RawPtr','RawSize','Entropy','Flags'))
    for sec in p.sections:
        raw = p.data[sec['rawptr']:sec['rawptr']+sec['rawsize']]
        print('%-10s 0x%08X 0x%08X 0x%08X 0x%08X %10.4f 0x%08X' % (
            sec['name'], sec['vaddr'], sec['vsize'], sec['rawptr'], sec['rawsize'],
            entropy(raw), sec['chars']))
    print()
    names = ['Export','Import','Resource','Exception','Security','BaseReloc','Debug','Arch',
             'GlobalPtr','TLS','LoadConfig','BoundImport','IAT','DelayImport','CLR','Reserved']
    for i,(rva,sz) in enumerate(p.dd):
        if rva or sz:
            off = p.rva2off(rva)
            print('DD[%2d] %-12s RVA=0x%08X size=%-8d off=%s' % (i, names[i] if i<16 else '?', rva, sz,
                  ('0x%X'%off) if off is not None else 'n/a'))
