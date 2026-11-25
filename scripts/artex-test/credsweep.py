#!/usr/bin/env python3
"""Credential-access sim (benign): read-only sweep of dummy credential-like
files, looped for ~12 s. Maps to FLASH T1552.001 (credentials in files),
T1555 (credentials from password stores), T1005 (data from local system).
Reads are NOT in AHR's inotify mask — this case measures exactly that
blind spot. No writes, no renames, no network."""
import os
import sys
import time

d = sys.argv[1]
files = []
for root, _, names in os.walk(d):
    for n in names:
        files.append(os.path.join(root, n))

end = time.time() + 12
while time.time() < end:
    for f in files:
        try:
            with open(f, "rb") as fh:
                fh.read()
        except OSError:
            pass
