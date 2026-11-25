#!/usr/bin/env python3
"""Ground-truth probe: count inotify events per second in a directory and
sample the entropy of written/moved files. Used to check whether a workload
really produces a burst, independent of AHR's sampling window."""
import ctypes, os, sys, time, struct, math

libc = ctypes.CDLL('libc.so.6', use_errno=True)
IN_NONBLOCK = 0o4000
IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE = 0x8, 0x40, 0x80, 0x100, 0x200

def shannon(path):
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
    except OSError:
        return None
    if not data:
        return None
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h / 8.0

watch = sys.argv[1]
seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0
fd = libc.inotify_init1(IN_NONBLOCK)
# recursive: add the dir itself and one level of subdirs
dirs = [watch]
for root, ds, _ in os.walk(watch):
    for d in ds:
        dirs.append(os.path.join(root, d))
    if root.count(os.sep) - watch.count(os.sep) > 2:
        break
for d in dirs:
    libc.inotify_add_watch(fd, d.encode(), IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE)
print(f"watching {len(dirs)} dirs under {watch} for {seconds}s")
start = time.time()
buckets = {}
max_ent = 0.0
while time.time() - start < seconds:
    try:
        buf = os.read(fd, 65536)
    except BlockingIOError:
        time.sleep(0.05)
        continue
    off = 0
    while off + 16 <= len(buf):
        wd, m, c, ln = struct.unpack_from("iIII", buf, off)
        name = buf[off+16:off+16+ln].rstrip(b"\0").decode(errors="replace")
        off += 16 + ln
        sec = int(time.time() - start)
        b = buckets.setdefault(sec, {"write": 0, "rename": 0, "create": 0})
        if m & IN_CLOSE_WRITE:
            b["write"] += 1
        if m & IN_MOVED_FROM:
            b["rename"] += 1
        if m & IN_CREATE:
            b["create"] += 1
        if m & (IN_CLOSE_WRITE | IN_MOVED_TO) and name:
            # resolve the file: find which watched dir this wd is — approximate
            # by trying the top dir; entropy sampling is best-effort here
            for d in dirs:
                p = os.path.join(d, name)
                e = shannon(p)
                if e is not None:
                    max_ent = max(max_ent, e)
                    break
for sec in sorted(buckets):
    print(f"  t+{sec}s: {buckets[sec]}")
print(f"max sampled entropy: {max_ent:.3f}")
