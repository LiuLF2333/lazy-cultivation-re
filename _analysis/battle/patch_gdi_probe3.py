# -*- coding: utf-8 -*-
"""probe3 = probe1 (15 GDI API counters) + per-call-site counters for the four
callers of the CreateCompatibleDC wrapper 0x44E710.

Counter layout (all inside writable .wash free tail):
    0x703EA0 + 4*i    probe1 API counters (15)
    0x703EE0 + 4*i    wrapper caller counters (4)
Thunks:
    0x6FE280 + 12*i   probe1 API thunks (15)
    0x6FE340 + 12*i   wrapper caller thunks (4)
"""
import hashlib
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
sys.path.insert(0, r"D:\XiuXian\_analysis\battle")
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import patch_battle_speed as P
import patch_gdi_probe as G

SRC = P.SRC
OUT = r"D:\XiuXian\懒人修仙传.probe3.exe"

SITE_THUNK_VA = 0x6FE340
SITE_CTR_VA = 0x703EE0
SITES = [0x44D1E4, 0x45201C, 0x4ADA24, 0x4E66C5]
WRAPPER = 0x44E710


def main():
    pe = PE(SRC)
    raw = bytearray(pe.raw)

    # ---------- speed patch ----------
    off_wait = pe.va2off(P.WAIT_VA)
    assert bytes(raw[off_wait:off_wait + 2]) == P.WAIT_ORIG
    off_hook = pe.va2off(P.HOOK_VA)
    assert bytes(raw[off_hook:off_hook + P.HOOK_LEN]) == P.HOOK_ORIG
    off_log = pe.va2off(P.LOGCHK_VA)
    assert bytes(raw[off_log:off_log + P.LOGCHK_LEN]) == P.LOGCHK_ORIG

    cave1 = P.build_cave1(P.CAVE_VA)
    cave2 = P.build_cave2(P.CAVE_VA + len(cave1))
    off_cave = pe.va2off(P.CAVE_VA)
    assert not any(raw[off_cave:off_cave + (P.FLAG_VA + 4) - P.CAVE_VA])
    raw[off_hook:off_hook + 5] = b"\xE8" + struct.pack("<i", P.CAVE_VA - (P.HOOK_VA + 5))
    raw[off_hook + 5:off_hook + P.HOOK_LEN] = b"\x90" * (P.HOOK_LEN - 5)
    cave2_va = P.CAVE_VA + len(cave1)
    raw[off_log:off_log + 5] = b"\xE8" + struct.pack("<i", cave2_va - (P.LOGCHK_VA + 5))
    raw[off_log + 5:off_log + P.LOGCHK_LEN] = b"\x90" * (P.LOGCHK_LEN - 5)
    raw[off_wait:off_wait + 2] = P.WAIT_NEW
    raw[off_cave:off_cave + len(cave1) + len(cave2)] = cave1 + cave2

    sh = pe.opt + pe.sizeopt
    for i in range(pe.nsec):
        o = sh + i * 40
        if raw[o:o + 8].rstrip(b"\x00").decode("latin1") == ".wash":
            chars = struct.unpack_from("<I", raw, o + 36)[0]
            struct.pack_into("<I", raw, o + 36, chars | 0x80000000)
            break

    # ---------- probe1 API counters ----------
    slots = G.import_slots(pe)
    text_off = pe.sections[0]["rawptr"]
    text_size = pe.sections[0]["rawsize"]
    text_va = 0x400000 + pe.sections[0]["va"]
    text = bytes(raw[text_off:text_off + text_size])
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    off_thunk = pe.va2off(G.THUNK_VA)
    off_count = pe.va2off(G.COUNTER_VA)
    assert not any(raw[off_thunk:off_thunk + len(G.APIS) * 12])
    assert not any(raw[off_count:off_count + 4 * len(G.APIS)])

    idx = 0
    api_report = []
    for name in G.APIS:
        iat = slots.get(name)
        if iat is None:
            api_report.append((name, 0))
            continue
        sites = []
        pat = b"\xFF\x15" + struct.pack("<I", iat)
        pos = 0
        while True:
            j = text.find(pat, pos)
            if j < 0:
                break
            # boundary check from the enclosing function prologue
            rel = j
            k = rel
            while k > 0 and not (text[k] == 0x55 and text[k + 1] == 0x8B and text[k + 2] == 0xEC):
                k -= 1
            ok = False
            posi = k
            while posi <= rel and k > 0:
                got = list(md.disasm(text[posi:posi + 15], text_va + posi, count=1))
                if not got:
                    break
                if posi == rel:
                    ok = True
                    break
                posi += got[0].size
            if ok:
                sites.append(text_va + j)
            pos = j + 1
        if not sites:
            api_report.append((name, 0))
            continue
        thunk_va = G.THUNK_VA + idx * 12
        counter_va = G.COUNTER_VA + idx * 4
        raw[off_thunk + idx * 12:off_thunk + (idx + 1) * 12] = (
            b"\xFF\x05" + struct.pack("<I", counter_va) +
            b"\xFF\x25" + struct.pack("<I", iat))
        for site in sites:
            o = pe.va2off(site)
            assert bytes(raw[o:o + 6]) == pat
            raw[o:o + 6] = b"\xE8" + struct.pack("<i", thunk_va - (site + 5)) + b"\x90"
        api_report.append((name, len(sites)))
        idx += 1

    # ---------- wrapper caller counters ----------
    off_sthunk = pe.va2off(SITE_THUNK_VA)
    off_sctr = pe.va2off(SITE_CTR_VA)
    assert not any(raw[off_sthunk:off_sthunk + 4 * 12]), "site thunk area busy"
    assert not any(raw[off_sctr:off_sctr + 16]), "site counter area busy"
    for i, site in enumerate(SITES):
        o = pe.va2off(site)
        assert raw[o] == 0xE8, "site 0x%08X is not a call" % site
        tgt = site + 5 + struct.unpack_from("<i", raw, o + 1)[0]
        assert tgt == WRAPPER, "site 0x%08X calls 0x%08X" % (site, tgt)
        thunk_va = SITE_THUNK_VA + i * 12
        ctr = SITE_CTR_VA + i * 4
        thunk = (b"\xFF\x05" + struct.pack("<I", ctr) +
                 b"\xE9" + struct.pack("<i", WRAPPER - (thunk_va + 11)) + b"\x90")
        raw[off_sthunk + i * 12:off_sthunk + (i + 1) * 12] = thunk
        raw[o:o + 5] = b"\xE8" + struct.pack("<i", thunk_va - (site + 5))

    # ---------- no ASLR (absolute operands in thunks) ----------
    dllchar = struct.unpack_from("<H", raw, pe.opt + 70)[0]
    struct.pack_into("<H", raw, pe.opt + 70, dllchar & ~0x40)

    open(OUT, "wb").write(bytes(raw))
    print("api counters:")
    for name, n in api_report:
        print("  %-24s sites=%d" % (name, n))
    print("wrapper caller counters:")
    for i, site in enumerate(SITES):
        print("  site 0x%08X ctr 0x%08X" % (site, SITE_CTR_VA + i * 4))
    print("output:", OUT)
    print("sha256:", hashlib.sha256(bytes(raw)).hexdigest())


if __name__ == "__main__":
    main()
