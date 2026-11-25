#!/usr/bin/env python3
"""Benign backup-style workload: copy files to a backup dir, renaming the
previous copy to .bak first. Low-entropy text only — the shape of an
encryptor (write + rename) without the entropy. Runs ~10 s."""
import os, shutil, sys, time

src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)
files = [os.path.join(src, f) for f in sorted(os.listdir(src))]
end = time.time() + 10
round_no = 0
while time.time() < end:
    round_no += 1
    for f in files:
        base = os.path.basename(f)
        cur = os.path.join(dst, base)
        bak = os.path.join(dst, base + ".bak")
        try:
            if os.path.exists(cur):
                os.rename(cur, bak)
            shutil.copyfile(f, cur)
        except FileNotFoundError:
            pass
    # tidy the .bak files so the next round renames again
    for f in list(os.listdir(dst)):
        if f.endswith(".bak"):
            try:
                os.remove(os.path.join(dst, f))
            except FileNotFoundError:
                pass
print(f"backup sim: {round_no} rounds")
