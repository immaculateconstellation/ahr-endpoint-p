#!/usr/bin/env python3
"""Dummy TCP listener on loopback only. Accepts connections and closes
them; counts attempts. No data leaves the machine. Used by spray.py
(password-spray sim) and beacon.py (C2 beacon sim)."""
import socket
import sys

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)
count = 0
while True:
    try:
        c, _ = srv.accept()
    except OSError:
        break
    count += 1
    if count % 200 == 0:
        print(f"listener:{port} accepted {count}", flush=True)
    c.close()
