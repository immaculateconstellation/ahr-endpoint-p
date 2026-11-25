#!/usr/bin/env python3
"""Fast chain in a fresh directory (benign): creates a subdirectory that
did not exist at AHR startup, runs the exfil pattern inside it for ~4 s,
then exits. Tests the watcher's new-directory race (IN_CREATE adds the
watch on the next drain) and the attribution window (a process that exits
before the next cycle cannot be attributed — the burst survives in the
10 s window as a host-level anomaly only)."""
import os
import sys
import time

fresh = sys.argv[1]
os.makedirs(fresh, exist_ok=True)
for i in range(8):
    with open(os.path.join(fresh, f"seed{i}.dat"), "wb") as f:
        f.write(b"A" * 4096)

t0 = time.time()
i = 0
while time.time() - t0 < 4:
    src = os.path.join(fresh, f"seed{i % 8}.dat")
    dst = os.path.join(fresh, f"enc{i % 8}.dat")
    fin = os.path.join(fresh, f"done{i % 8}.dat")
    try:
        with open(src, "rb") as f:
            data = f.read()
        with open(dst, "wb") as f:
            f.write(os.urandom(len(data)))
        os.rename(dst, fin)
    except FileNotFoundError:
        pass
    i += 1
