#!/bin/bash
# AHR vs ARTEX (FBI FLASH-20261113-001) — synthetic behavior test.
# ALL scenarios are benign simulations run in AHR DRY-RUN mode.
# No ARTEX code was fetched, built, or run; no live enforcement;
# no processes are touched by AHR. Sims are loopback/scratch only.
# Modeled on ../gootloader-test/run.sh (same run_case pattern).
# Run from anywhere: ./scripts/artex-test/run.sh
set -u
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d /tmp/ahr-artex-test.XXXXXX)"
export AHR_TEST_DIR="$T"
BIN=$T/bin
PORT=18123
mkdir -p "$BIN" "$T/stage" "$T/creds" "$T/logs"
cd ~/workspace/ahr-work || exit 1

# --- sim binaries (comm name = file name, via sysinfo /proc stat) ---
cp -f /usr/bin/yes "$BIN/artex-agent"   # ARTEX agent name, spins 100% CPU
cp -f /usr/bin/yes "$BIN/pwsh"         # T1059 name for the chain step
cp -f /usr/bin/yes "$BIN/worker-sim"   # benign hot name (control)

# --- dummy credential tree: 120 fake files, no real secrets ---
for i in $(seq 1 30); do
    printf 'FAKE-RSA-PRIVATE-KEY-%s\n' "$i" > "$T/creds/id_rsa_$i"
    printf 'FAKE-PEM-CERT-%s\n' "$i" > "$T/creds/file_$i.pem"
    printf 'FAKE_AWS_KEY=AKIAFAKE%s\nFAKE_AWS_SECRET=fake%s\n' "$i" "$i" > "$T/creds/aws_$i.env"
    printf 'FAKE_PASSWORD=dummy-%s\n' "$i" > "$T/creds/pass_$i.env"
done

PIDS=()
AHR_PID=""
cleanup() {
    [ -n "$AHR_PID" ] && kill "$AHR_PID" 2>/dev/null
    AHR_PID=""
    for g in "${PIDS[@]}"; do kill -- "-$g" 2>/dev/null; done
    PIDS=()
}
# Scratch is bounded (8 x 4 KB rotating files); remove it on exit.
trap 'cleanup; rm -rf "$T"' EXIT

echo "=== building AHR (release) ==="
cargo build --release --offline 2>&1 | tail -3
AHR=~/workspace/ahr-work/target/release/ahr-endpoint
[ -x "$AHR" ] || { echo "BUILD FAILED"; exit 1; }

run_case() {
    local name="$1"; shift
    echo ""
    echo "===== $name ====="
    PIDS=()
    "$@"  # start sims; each start_* sets PIDS
    sleep 2  # let CPU deltas settle
    RUST_LOG=info AHR_WATCH_PATHS="$T/stage" AHR_AUDIT_LOG="$T/logs/audit-$name.jsonl" \
        timeout 30 "$AHR" --dry-run --once 2>&1 | grep -E "DRY-RUN|Potential|Single-cycle|File-activity|anomaly" || true
    echo "--- audit record ($name) ---"
    cat "$T/logs/audit-$name.jsonl" 2>/dev/null || echo "(no audit record — no detection)"
    cleanup
    sleep 1
}

# Background-AHR variant for multi-second chains: AHR loops cycles
# (no --once) while the sim runs, then is killed and its log read.
run_case_bg() {
    local name="$1"; sim="$2"
    echo ""
    echo "===== $name ====="
    PIDS=()
    AHR_PID=""
    RUST_LOG=info AHR_WATCH_PATHS="$T/stage" AHR_AUDIT_LOG="$T/logs/audit-$name.jsonl" \
        "$AHR" --dry-run > "$T/logs/ahr-$name.log" 2>&1 &
    AHR_PID=$!
    sleep 1  # let AHR finish its startup warm-up
    $sim     # runs the sim; start_* helpers set PIDS
    sleep 4  # one more cycle after the sim exits
    kill "$AHR_PID" 2>/dev/null; wait "$AHR_PID" 2>/dev/null; AHR_PID=""
    echo "--- AHR output ($name) ---"
    grep -E "DRY-RUN|Potential|Single-cycle|File-activity|anomaly" "$T/logs/ahr-$name.log" || echo "(no detection lines)"
    echo "--- audit record ($name) ---"
    cat "$T/logs/audit-$name.jsonl" 2>/dev/null || echo "(no audit record — no detection)"
    cleanup
    sleep 1
}

start_none() { :; }
start_artex_hot() { setsid "$BIN/artex-agent" >/dev/null 2>&1 & PIDS+=($!); }
start_spray() {
    setsid python3 "$SCRIPT_DIR/listener.py" "$PORT" >/dev/null 2>&1 & PIDS+=($!)
    sleep 1
    setsid python3 "$SCRIPT_DIR/spray.py" "$PORT" >/dev/null 2>&1 & PIDS+=($!)
}
start_credsweep() { setsid python3 "$SCRIPT_DIR/credsweep.py" "$T/creds" >/dev/null 2>&1 & PIDS+=($!); }
start_exfil() { setsid python3 "$SCRIPT_DIR/exfil.py" "$T/stage" >/dev/null 2>&1 & PIDS+=($!); }
start_beacon() {
    setsid python3 "$SCRIPT_DIR/listener.py" "$PORT" >/dev/null 2>&1 & PIDS+=($!)
    sleep 1
    setsid python3 "$SCRIPT_DIR/beacon.py" "$PORT" >/dev/null 2>&1 & PIDS+=($!)
}
start_chain() { python3 "$SCRIPT_DIR/chain.py" "$T/stage" "$T/creds" "$BIN"; }
start_freshchain() { python3 "$SCRIPT_DIR/freshchain.py" "$T/stage/fresh"; }

run_case A0-baseline-no-sims start_none
run_case A1-artex-agent-hot start_artex_hot
run_case A2-password-spray start_spray
run_case A3-credential-sweep start_credsweep
run_case A4-exfil-plain-name start_exfil
run_case A5-c2-beacon start_beacon
run_case_bg A6a-compressed-chain start_chain
run_case_bg A6b-fresh-dir-chain start_freshchain

echo ""
echo "=== done === (scratch dir $T removed on exit)"
