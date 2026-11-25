#!/usr/bin/env python3
"""Password-spray sim (benign): rapid connection attempts against a local
dummy listener on loopback, plus a short-lived child process every 15
attempts. No real target, no credentials tried, nothing leaves the
machine. Maps to the FLASH's "high volumes of failed attempts" and
"sequential enumeration against login endpoints" indicators, and to
T1110.003 (password spraying). AHR has no network telemetry and its
sampler runs on a 3 s cycle — this case measures both blind spots."""
import os
import socket
import subprocess
import sys
import time

port = int(sys.argv[1])
end = time.time() + 12
n = 0
while time.time() < end:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
        s.close()
    except OSError:
        pass
    n += 1
    if n % 15 == 0:
        subprocess.Popen(["/bin/sleep", "0.05"])
    time.sleep(0.005)
