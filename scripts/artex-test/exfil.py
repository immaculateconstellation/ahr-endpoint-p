#!/usr/bin/env python3
"""S7-style staging/exfil sim (benign): read a file, write high-entropy
bytes, rename — rotating over 8 destination names so disk stays bounded.
Maps to FLASH T1074 (data staged) / T1005 (data from local system) /
T1486-style behavior. Nothing leaves the scratch dir."""
import os
import sys

d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.environ.get("AHR_TEST_DIR", "/tmp"), "stage")
os.makedirs(d, exist_ok=True)
for i in range(8):
    with open(os.path.join(d, f"seed{i}.dat"), "wb") as f:
        f.write(b"A" * 4096)

i = 0
while True:
    src = os.path.join(d, f"seed{i % 8}.dat")
    dst = os.path.join(d, f"enc{i % 8}.dat")
    fin = os.path.join(d, f"done{i % 8}.dat")
    try:
        with open(src, "rb") as f:
            data = f.read()
        with open(dst, "wb") as f:
            f.write(os.urandom(len(data)))
        os.rename(dst, fin)
    except FileNotFoundError:
        pass
    i += 1
