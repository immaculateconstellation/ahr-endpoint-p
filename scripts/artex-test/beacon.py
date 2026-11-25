#!/usr/bin/env python3
"""C2 beacon sim (benign): periodic outbound connection to a local dummy
listener on loopback, every 2 s. Maps to FLASH T1071.001 (web protocols),
T1090 (proxy), T1572 (protocol tunneling). AHR has no network telemetry —
this case measures that blind spot. Low CPU, plain name, no file I/O."""
import socket
import sys
import time

port = int(sys.argv[1])
while True:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1)
        s.sendall(b"BEACON")
        s.close()
    except OSError:
        pass
    time.sleep(2)
