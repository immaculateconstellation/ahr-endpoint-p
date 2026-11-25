#!/bin/bash
# AHR vs Gootloader (FBI FLASH CC-111626-MW) — synthetic behavior test.
# ALL scenarios are benign simulations run in AHR DRY-RUN mode.
# No malware, no live enforcement, no processes are touched by AHR.
# Each scenario: start sim process(es), let CPU settle, run one AHR cycle.
#
# Persisted from /tmp (2026-11-18) so the test survives VM restarts.
# Run from anywhere: ./scripts/gootloader-test/run.sh
set -u
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d /tmp/ahr-gootloader-test.XXXXXX)"
export AHR_TEST_DIR="$T"
BIN=$T/bin
mkdir -p "$BIN" "$T/churn" "$T/logs"
cd ~/workspace/ahr-work || exit 1

# --- sim binaries (comm name = file name, via sysinfo /proc stat) ---
cp -f /usr/bin/yes "$BIN/pwsh"            # T1059 name, spins 100% CPU
cp -f /usr/bin/yes "$BIN/encryptor-sim"   # T1486 name, spins 100% CPU
cp -f /usr/bin/yes "$BIN/worker-sim"      # benign name, spins 100% CPU
cp -f /bin/sleep "$BIN/pwsh-idle"         # T1059 name, idle (sleep)
cp -f "$(command -v python3)" "$BIN/pwsh-chain"  # T1059 name, spawns tree

# --- tree scripts: parent (pwsh-chain) -> level2 -> level3, only parent spins ---
cat > "$T/level3.py" <<'EOF'
import time
time.sleep(120)
EOF
cat > "$T/level2.py" <<'EOF'
import subprocess, time, sys, os
subprocess.Popen([sys.executable, os.path.join(os.environ["AHR_TEST_DIR"], "level3.py")])
time.sleep(120)
EOF
cat > "$T/chain.py" <<'EOF'
import subprocess, time, sys, os
subprocess.Popen([sys.executable, os.path.join(os.environ["AHR_TEST_DIR"], "level2.py")])
while True:
    pass
EOF

# --- file-churn sim: mass renames, innocuous name, low CPU ---
cat > "$T/churn.py" <<'EOF'
import os, time
d = os.path.join(os.environ["AHR_TEST_DIR"], "churn")
for i in range(50):
    open(os.path.join(d, f"f{i}.dat"), "w").write("x" * 4096)
i = 0
while True:
    a = os.path.join(d, f"f{i % 50}.dat")
    b = os.path.join(d, f"g{i % 50}.dat")
    try:
        os.rename(a, b)
    except FileNotFoundError:
        try:
            os.rename(b, a)
        except FileNotFoundError:
            pass
    i += 1
    time.sleep(0.005)
EOF

PIDS=()
cleanup() {
    for g in "${PIDS[@]}"; do kill -- "-$g" 2>/dev/null; done
    PIDS=()
}
# Scratch holds tens of thousands of sim files (/tmp is a small tmpfs);
# remove it on exit. Audit records are printed inline above.
trap 'cleanup; rm -rf "$T"' EXIT

echo "=== building AHR (release) ==="
cargo build --release 2>&1 | tail -3
AHR=~/workspace/ahr-work/target/release/ahr-endpoint
[ -x "$AHR" ] || { echo "BUILD FAILED"; exit 1; }

run_case() {
    local name="$1"; shift
    echo ""
    echo "===== $name ====="
    PIDS=()
    "$@"  # start sims; each start_* sets PIDS
    sleep 2  # let CPU deltas settle
    RUST_LOG=info AHR_WATCH_PATHS="$T/churn" AHR_AUDIT_LOG="$T/logs/audit-$name.jsonl" \
        timeout 30 "$AHR" --dry-run --once 2>&1 | grep -E "DRY-RUN|Potential|Single-cycle|File-activity|anomaly" || true
    echo "--- audit record ($name) ---"
    cat "$T/logs/audit-$name.jsonl" 2>/dev/null || echo "(no audit record — no detection)"
    cleanup
    sleep 1
}

start_none() { :; }
start_pwsh_hot()   { setsid "$BIN/pwsh" >/dev/null 2>&1 & PIDS+=($!); }
start_encryptor()  { setsid "$BIN/encryptor-sim" >/dev/null 2>&1 & PIDS+=($!); }
start_chain()      { setsid "$BIN/pwsh-chain" "$T/chain.py" >/dev/null 2>&1 & PIDS+=($!); }
start_worker_hot() { setsid "$BIN/worker-sim" >/dev/null 2>&1 & PIDS+=($!); }
start_pwsh_idle()  { setsid "$BIN/pwsh-idle" 60 >/dev/null 2>&1 & PIDS+=($!); }
start_churn()      { setsid python3 "$T/churn.py" >/dev/null 2>&1 & PIDS+=($!); }
start_encryptor_py() { setsid python3 "$SCRIPT_DIR/encryptor.py" >/dev/null 2>&1 & PIDS+=($!); }

run_case S0-baseline-no-sims start_none
run_case S1-T1059-pwsh-hot start_pwsh_hot
run_case S2-T1486-encryptor-hot start_encryptor
run_case S3-T1059-chain-depth2 start_chain
run_case S4-benign-hot-worker start_worker_hot
run_case S5-T1059-pwsh-idle start_pwsh_idle
run_case S6-file-churn-no-name start_churn
run_case S7-encryptor-attributed start_encryptor_py

echo ""
echo "=== done === (scratch dir $T removed on exit)"
