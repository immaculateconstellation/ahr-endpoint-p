#!/usr/bin/env python3
"""Realistic encryptor simulation (benign): read a file, write high-entropy
bytes, rename — as fast as possible, no sleeps. Nothing leaves the scratch dir."""
import os, sys

d = os.path.join(os.environ.get("AHR_TEST_DIR", "/tmp/ahr-gootloader-test"), "churn")
os.makedirs(d, exist_ok=True)
# seed files
for i in range(20):
    with open(os.path.join(d, f"seed{i}.dat"), "wb") as f:
        f.write(b"A" * 4096)

i = 0
while True:
    src = os.path.join(d, f"seed{i % 20}.dat")
    dst = os.path.join(d, f"enc{i}.dat")
    try:
        with open(src, "rb") as f:
            data = f.read()
        # "encrypt": overwrite with high-entropy bytes, then rename
        with open(dst, "wb") as f:
            f.write(os.urandom(len(data)))
        os.rename(dst, os.path.join(d, f"done{i}.dat"))
    except FileNotFoundError:
        pass
    i += 1
