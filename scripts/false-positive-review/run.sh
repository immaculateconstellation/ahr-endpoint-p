#!/bin/bash
# AHR false-positive review — benign workloads under the file watcher.
# All cases are ordinary, benign file activity run in AHR DRY-RUN mode.
# Nothing is enforced; AHR only reports what it *would* flag.
#
# Purpose: the 2026-11-18 file-telemetry fix made AHR sensitive to bulk
# file activity. A detector that flags ordinary builds, copies, and
# backups is not usable, so these workloads measure exactly that.
# Run: ./scripts/false-positive-review/run.sh
set -u
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d /tmp/ahr-fp-review.XXXXXX)"
WORK=$T/work
LOGS=$T/logs
mkdir -p "$WORK" "$LOGS"
cd ~/workspace/ahr-work || exit 1

echo "=== building AHR (release) ==="
cargo build --release 2>&1 | tail -3
AHR=~/workspace/ahr-work/target/release/ahr-endpoint
[ -x "$AHR" ] || { echo "BUILD FAILED"; exit 1; }

# --- fixture: a source tree of mostly-text files ---
python3 - "$WORK" <<'PYEOF'
import os, sys
root = sys.argv[1]
tree = os.path.join(root, "src-tree")
os.makedirs(tree, exist_ok=True)
for i in range(150):
    kind = i % 3
    if kind == 0:
        text = ("// module %d\nfn f%d() -> u32 { %d }\n" % (i, i, i)) * 40
        name = f"mod{i}.rs"
    elif kind == 1:
        text = ("# note %d\nThe quick brown fox jumps over the lazy dog.\n" % i) * 60
        name = f"doc{i}.md"
    else:
        text = ("line %d: lorem ipsum dolor sit amet\n" % i) * 80
        name = f"data{i}.txt"
    with open(os.path.join(tree, name), "w") as f:
        f.write(text)
print("fixture tree:", tree)
PYEOF

# --- fixture: a small Rust crate with many modules (for the build case) ---
python3 - "$WORK/crate" <<'PYEOF'
import os, sys
root = sys.argv[1]
os.makedirs(os.path.join(root, "src"), exist_ok=True)
with open(os.path.join(root, "Cargo.toml"), "w") as f:
    f.write('[package]\nname = "fp-test"\nversion = "0.1.0"\nedition = "2021"\n')
mods = []
with open(os.path.join(root, "src", "lib.rs"), "w") as f:
    for i in range(60):
        mods.append(f"pub mod m{i};")
        with open(os.path.join(root, "src", f"m{i}.rs"), "w") as g:
            g.write("\n".join(f"pub fn f{j}(x: u32) -> u32 {{ x.wrapping_add({j}) }}" for j in range(20)) + "\n")
    f.write("\n".join(mods) + "\n")
print("fixture crate:", root)
PYEOF
tar -cf "$WORK/arc.tar" -C "$WORK" src-tree
# Pre-build the crate once so target/ exists and is watched from the
# start (see the B1 note above), and pre-create the backup dir so its
# watch path exists at AHR init — a path that appears only after
# startup is picked up by the periodic re-scan, but the test should
# not depend on that timing.
(cd "$WORK/crate" && cargo build -q)
mkdir -p "$WORK/backup"

PIDS=()
cleanup() {
    for g in "${PIDS[@]}"; do kill -- "-$g" 2>/dev/null; done
    PIDS=()
}
# Scratch holds build outputs and copies (/tmp is a small tmpfs);
# remove it on exit. Audit records are printed inline above.
trap 'cleanup; rm -rf "$T"' EXIT

run_case() {
    local name="$1"; local watch="$2"; shift 2
    echo ""
    echo "===== $name (watch: $watch, continuous ~16 s) ====="
    PIDS=()
    # AHR FIRST, workload second: the agent is already running when
    # the user copies files. (The first version started the workload
    # first — a 12-iteration copy of 150 small files finishes in
    # ~50 ms, before AHR's watches even exist, so "clean" meant
    # "never saw it", not "saw it and passed".)
    RUST_LOG=info AHR_WATCH_PATHS="$watch" AHR_AUDIT_LOG="$LOGS/audit-$name.jsonl" \
        timeout 16 "$AHR" --dry-run > "$LOGS/stdout-$name.log" 2>&1 &
    local AHRPID=$!
    sleep 2  # let AHR init its watches
    "$@"  # start workload; each start_* sets PIDS
    wait $AHRPID
    grep -E "DRY-RUN would|DRY-RUN decision|File-activity signal|DRY-RUN file" "$LOGS/stdout-$name.log" || echo "(no flags in 16 s)"
    echo "--- audit summary ($name) ---"
    if [ -f "$LOGS/audit-$name.jsonl" ]; then
        echo "records: $(wc -l < "$LOGS/audit-$name.jsonl") (process flags: $(grep -c '"process_name"' "$LOGS/audit-$name.jsonl" || true), host anomalies: $(grep -c 'file-activity-anomaly' "$LOGS/audit-$name.jsonl" || true))"
        head -1 "$LOGS/audit-$name.jsonl"
    else
        echo "(no audit record — no detection)"
    fi
    cleanup
    sleep 1
}

# B1: rebuild a 60-module crate in a loop (writes + renames + compiler entropy).
# No `cargo clean`: the crate is pre-built once below so target/ exists
# and is watched from the start, and rebuilds rewrite files in place
# (touch forces a recompile). A clean+build loop recreates target/ fresh
# each time and the new subdirs outrun the watcher — that tests the
# watcher's fresh-dir race, not the build.
start_build() {
    setsid bash -c "cd '$WORK/crate' && for i in 1 2 3 4 5; do touch src/lib.rs; cargo build -q; done" >/dev/null 2>&1 & PIDS+=($!);
}
# B2: bulk-copy the tree into an EXISTING dir, looped (many writes,
# low entropy, no renames). The destination must pre-exist: files
# written into a fresh subdir are invisible until the watcher picks
# the new dir up, which a fast loop outruns.
mkdir -p "$WORK/copy/dst"
start_copy() {
    setsid bash -c "for i in \$(seq 1 12); do cp -r '$WORK/src-tree/.' '$WORK/copy/dst/'; done" >/dev/null 2>&1 & PIDS+=($!);
}
# B3: extract a tarball into an EXISTING dir, looped (writes + creates).
mkdir -p "$WORK/tar/ext"
start_tar() {
    setsid bash -c "for i in \$(seq 1 12); do tar -xf '$WORK/arc.tar' -C '$WORK/tar/ext' --strip-components=1; done" >/dev/null 2>&1 & PIDS+=($!);
}
# B4: backup-style script — copy files, rename the previous copy to .bak
start_backup() {
    setsid python3 "$SCRIPT_DIR/backup_sim.py" "$WORK/src-tree" "$WORK/backup" >/dev/null 2>&1 & PIDS+=($!);
}

run_case B1-cargo-build "$WORK/crate" start_build
run_case B2-bulk-copy "$WORK/copy" start_copy
run_case B3-tar-extract "$WORK/tar" start_tar
run_case B4-backup-renames "$WORK/backup" start_backup

echo ""
echo "=== done === (scratch dir $T removed on exit)"
