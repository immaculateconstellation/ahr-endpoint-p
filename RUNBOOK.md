# AHR-Endpoint — Runbook (v0.3.0 release, 2026-11-10, safe-by-default build)

Adaptive Hollow Reflector — experimental Rust endpoint-security agent.
Research prototype. Linux x86_64. Built locally 2026-11-10; this bundle
was prepared locally only and has not been published or sent anywhere.

**Safety change in this build: dry-run is now the default.** With no
flags the agent watches, scores, and reports without touching a
process. Live enforcement requires an explicit `--live` flag, prints
a warning banner, and waits 3 seconds before the first cycle.
`--help` / `-h` prints usage and exits without starting the agent;
unknown flags are rejected the same way. This change was made because
an earlier build started its live loop on a bare `--help` check.

## Bundle contents

- `ahr-endpoint` — release binary (3,508,784 bytes)
  SHA-256: `42c54c1e4a92c06f8ab63700db6fda8a624c9f29fa639509ac14ad8b35210749`

  Rebuilt 2026-11-18 during the pre-open-source exposure audit: the
  2026-11-10 binary embedded build-machine paths (registry paths under
  the builder's home directory) in its panic-location strings. The
  rebuild uses `strip = true` plus `scripts/build_release.sh`, which
  remaps the builder's home directory out of embedded paths; the new
  binary was verified to contain no build-machine path strings, and
  `run-dry-run.sh` was re-run against it successfully. Previous binary
  SHA-256 was `5fac9b4bc4d35a3da60c32ab348a84693d6635465fc390fdc405a94194ca0998`.
  Tests at rebuild time: 33 passed, 0 failed (37 with `--features ebpf`).
- `run-dry-run.sh` — starter script: runs the agent dry-run, one
  cycle, and exits. The safe way to take a first look.
- `README.md` — project overview, detection/response model, layout
- `STATUS.md` — what works today, what is not established, next steps
- `LICENSE` — IOF Attribution License v1.0. Any public use, derivative
  work, or implementation must clearly attribute
  "AHR-Endpoint / Adaptive Hollow Reflector by Gregory Scott Davis,
  Princeton, NC."

Built with: `cargo build --release` (default features only, no eBPF).
Tests at build time: 23 passed, 0 failed (16 unit + 3 integration +
7 CLI/arg-parsing tests, including a live-detection test).
Static dry-run audit (`python3 scripts/dry_run_audit.py`): passed.
Rust 1.99.1.

## First: dry-run (safe, recommended first step)

Dry-run is the default mode. It evaluates detections and reports
intended actions without loading eBPF, sending process signals, or
publishing NATS invariants.

```bash
# Easiest first look (starter script — dry-run, one cycle, exit):
./run-dry-run.sh

# Same thing by hand:
RUST_LOG=info ./ahr-endpoint --dry-run --once

# Continuous dry-run loop (3-second cycles, stop with Ctrl-C):
RUST_LOG=info ./ahr-endpoint --dry-run

# No flags at all also runs dry-run:
RUST_LOG=info ./ahr-endpoint --once
```

Dry-run needs nothing else: no NATS server, no special permissions,
no network. Optional environment variables:

- `AHR_AUDIT_LOG=<path>` — append every decision as a JSONL audit
  record (pid, name, both risk scores, effective risk, recommendation,
  executable action, `dry_run`, `applied`).
- `AHR_SENTINELX_SINK=<path>` — append Sentinel X evidence events as
  JSONL (live mode only; nothing is emitted in dry-run).

To see all flags without starting the agent:

```bash
./ahr-endpoint --help
```

## Live mode (enforces — isolated test environment only)

Live mode is explicit opt-in only:

```bash
RUST_LOG=info ./ahr-endpoint --live --once
```

With `--live` the agent prints a warning banner and waits 3 seconds
before the first cycle, so it can be stopped with Ctrl-C. A matching
signal can then lead to SIGSTOP or SIGKILL actions on a process tree,
after a short jittered dispatch delay. Exercise only in an isolated
environment after reviewing detection thresholds, response policy,
audit logging, and rollback behavior. Never run `--live` on a machine
with real work until dry-run behavior has been reviewed there first.

What live mode does and needs:

- **Detection:** process-name indicators (`ransom`, `encrypt`,
  `locker`, `cryptor`, `cmd`, `powershell`, `pwsh`) combined with
  CPU > 40% or memory > ~500 MB. At startup the agent waits ~400 ms
  warming up its process snapshot so the first cycle already sees a
  valid CPU reading (previously the first cycle always read 0.0 CPU).
- **Response:** graduated Soft (SIGSTOP) → Medium (SIGSTOP tree) →
  Kill (SIGKILL tree), by effective risk. PID 1 and the agent's own
  PID are whitelisted and never flagged.
- **Authorization cap:** privilege-escalated recommendations
  (RevokeSession, IsolateHost, TriggerMfaReprompt) are recorded, never
  auto-executed; where one would otherwise mean killing a tree, the
  executable action is held at suspend pending human authorization.
- **NATS (optional):** the agent tries `nats://localhost:4222` for
  cross-host invariants and Sentinel X evidence. If no broker is
  there it logs "NATS not available (standalone mode)" and continues
  standalone. Start one for development with:
  `docker run --rm -p 4222:4222 nats:latest`
- **eBPF (not in this build):** the kernel path is inactive — this
  binary was built without `--features ebpf`. The agent logs
  "Kernel eBPF enforcement: inactive" and continues with userspace
  graduated response only. The eBPF path needs a compatible kernel,
  nightly components, `bpf-linker`, privileges, and a compiled object
  (see README.md / `docs/eBPF_Enforcement.md` in the source tree).
- **Privileges:** the agent must run as a user able to signal the
  processes it targets. As root it can signal anything; as a regular
  user only its own processes. Run it as the least-privileged user
  that still covers the processes it is meant to watch.

## Verified behavior (2026-11-10, local lab)

- `cargo test`: 23 passed, 0 failed (debug; release build also
  verified). Static dry-run audit: passed.
- `--help` exits 0 with usage and starts nothing; `-h` the same.
  Unknown flags (e.g. `--bogus`) and conflicting `--live --dry-run`
  exit 2 with usage and start nothing.
- No flags at all runs dry-run: a looping run with no flags logged
  the DRY-RUN banner and only reported what it *would* do.
- Dry-run single cycle flags a CPU-spinning synthetic target at
  risk 9 on the first cycle (`--dry-run --once`).
- Live end-to-end, release binary, no NATS, no eBPF: a CPU spinner
  (94.7% CPU) and a memory holder (596 MB) under suspicious names
  were each contained (SIGKILL tree) one per 3-second cycle; audit
  records show `dry_run: false, applied: true` for those two targets
  only; Sentinel X evidence events were emitted as CRITICAL
  (threat_index 90, MITRE T1486); a before/after process-list
  comparison confirmed no other process was harmed.
- Live opt-in proof (this build): `--live --once` against a fresh
  synthetic CPU spinner (80.7% CPU, ~10 MB, suspicious name) printed
  the LIVE MODE banner, waited 3 seconds, then contained it
  (SIGKILL); audit record `dry_run: false, applied: true`,
  `effective_risk: 9`; Sentinel X CRITICAL event (threat_index 90,
  MITRE T1486); before/after process diff showed no other process
  changed; all synthetic processes and temp files cleaned up.

## Honest limits (from STATUS.md — read before relying on this)

- Research prototype. No validated behavioral-detection benchmarks
  or false-positive rates.
- No measured sub-second containment and no production host
  isolation, session revocation, or network quarantine behavior.
- Detection is prototype-grade heuristics (name + resource
  pressure). Expect false positives on legitimately busy processes
  whose names contain an indicator substring (e.g. anything with
  "encrypt" in the name doing heavy work).
- The telemetry scorer mostly reflects what the userspace detector
  observed; richer file telemetry (entropy, write velocity, rename
  bursts) is populated only by the eBPF path, which is not in this
  build.
- Deployment and cross-host latency claims require measurement;
  none has been done.
