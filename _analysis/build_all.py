"""Reproduce 懒人修仙传.final.exe from the pristine 1.1.1.11 executable.

Chain (each stage's output is the next stage's input):

    pristine  --patch_wild_autocollect.py-->  .wild.exe
              --patch_battle_speed.py----->  .speed3.exe     (3 hooks + 2 caves)
              --patch_dungeon_retry3.py--->  .final.exe      (new auto-retry)

The GDI leak fix is part of patch_battle_speed.py, the dungeon auto-collect /
wild automation is part of patch_wild_autocollect.py.

Usage:  python build_all.py [--install]
"""

import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable

PRISTINE = os.path.join(ROOT, "懒人修仙传.exe")          # verified by hash below
WILD = os.path.join(ROOT, "懒人修仙传.wild.exe")
SPEED = os.path.join(ROOT, "懒人修仙传.speed3.exe")
FINAL = os.path.join(ROOT, "懒人修仙传.final.exe")

PRISTINE_SHA256 = "A84DE8DC435C7765E38A62C89C6ABFEEFF4A1E80D8D04C707407AC52C20556D5"
FINAL_SHA256 = "563B70FBC4CC9DC657B292E2DE753B4F2C07DE5B84F96E45A196CC90B9D61185"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


BATTLE = os.path.join(HERE, "battle")


def run(script, *args):
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        path = os.path.join(BATTLE, script)
    cmd = [PY, path] + list(args)
    print("\n$ %s %s" % (script, " ".join(args)))
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode != 0:
        raise SystemExit("stage failed: %s (exit %d)" % (script, r.returncode))


def find_pristine():
    """patch_wild_autocollect.py insists on the pristine hash; make sure the
    installed executable is not what it picks up when it is already patched."""
    if os.path.isfile(PRISTINE) and sha256(PRISTINE) == PRISTINE_SHA256:
        return PRISTINE
    import glob
    for path in sorted(glob.glob(PRISTINE + ".bak.*"), reverse=True):
        if sha256(path) == PRISTINE_SHA256:
            return path
    raise SystemExit("no pristine executable (sha256 %s...) found" % PRISTINE_SHA256[:16])


def main():
    install = "--install" in sys.argv
    src = find_pristine()
    print("pristine:", src)

    # stage 1: wild automation (writes ROOT\懒人修仙传.wild.exe itself)
    run("patch_wild_autocollect.py")
    print("wild    :", sha256(WILD)[:16])

    # stage 2: battle speed-up + GDI leak fix
    run("patch_battle_speed.py", SPEED, WILD)
    print("speed   :", sha256(SPEED)[:16])

    # stage 3: reliable dungeon auto-retry
    run("patch_dungeon_retry3.py", SPEED, FINAL)
    got = sha256(FINAL)
    print("\nfinal   :", got)
    if got != FINAL_SHA256:
        print("WARNING: hash differs from the audited build (%s...)"
              % FINAL_SHA256[:16])

    if install:
        backup = PRISTINE + ".bak.install"
        if not os.path.exists(backup):
            with open(PRISTINE, "rb") as f, open(backup, "wb") as g:
                g.write(f.read())
        with open(FINAL, "rb") as f, open(PRISTINE, "wb") as g:
            g.write(f.read())
        print("installed ->", PRISTINE)


if __name__ == "__main__":
    main()
