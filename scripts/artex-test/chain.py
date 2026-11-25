#!/usr/bin/env python3
"""Compressed chain sim (benign): recon reads -> hot pwsh-named process ->
exfil. Runs ~9 s total, then exits. All inside the scratch dir. Tests
whether AHR catches a fast-chained intrusion in a pre-existing watched
directory — the on-box shape of the FLASH's "under three hours to
privileged access" claim, compressed."""
import os
import subprocess
import sys
import time

stage, creds, bin_dir = sys.argv[1], sys.argv[2], sys.argv[3]

# 1. recon: read the credential tree (2 s)
files = []
for root, _, names in os.walk(creds):
    for n in names:
        files.append(os.path.join(root, n))
t0 = time.time()
while time.time() - t0 < 2:
    for f in files:
        try:
            with open(f, "rb") as fh:
                fh.read()
        except OSError:
            pass

# 2. hot pwsh-named process (3 s) — FLASH T1059.001
p = subprocess.Popen([os.path.join(bin_dir, "pwsh")])
time.sleep(3)
p.kill()
p.wait()

# 3. exfil: read -> urandom write -> rename (4 s)
os.makedirs(stage, exist_ok=True)
for i in range(8):
    with open(os.path.join(stage, f"seed{i}.dat"), "wb") as f:
        f.write(b"A" * 4096)
t0 = time.time()
i = 0
while time.time() - t0 < 4:
    src = os.path.join(stage, f"seed{i % 8}.dat")
    dst = os.path.join(stage, f"enc{i % 8}.dat")
    fin = os.path.join(stage, f"done{i % 8}.dat")
    try:
        with open(src, "rb") as f:
            data = f.read()
        with open(dst, "wb") as f:
            f.write(os.urandom(len(data)))
        os.rename(dst, fin)
    except FileNotFoundError:
        pass
    i += 1
