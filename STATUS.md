# AHR-Endpoint — status

**Version:** 0.3.0  
**Updated:** 2026-11-18

## Public boundary

Research prototype. Userspace Rust agent with optional Aya/eBPF loader path and experimental enforcement scaffolding. Does **not** claim measured sub-second containment, production readiness, or universal ransomware detection.

## Working today

- Userspace agent loop with process-name + resource-pressure heuristics (`src/detection.rs`)
- Merged version 06 telemetry scoring model in the active engine (`src/hollow.rs`): weighted signal scoring with human-readable `score_reasons`, decoy suppression, injection-API weighting, privilege-aware recommendations, and companion actions — unit-tested in the crate
- Decision policy layer (`src/policy.rs`): effective risk is the more severe of the detector ladder and the telemetry score, both kept in the audit record; privilege-escalated recommendations (session revocation, host isolation, MFA reprompt) are held at suspend pending human authorization, never auto-executed
- Structured audit logging (`src/audit.rs`): one JSON record per decision, optionally appended as JSONL via `AHR_AUDIT_LOG`
- Sentinel X evidence stream (`src/sentinel.rs`): decisions emitted as evidence events on the `sentinelx.evidence` NATS subject and/or a local JSONL sink (`AHR_SENTINELX_SINK`)
- Graduated response scaffolding (observe / suspend / isolate / terminate concepts)
- Process-tree controls with basic whitelist considerations
- Optional NATS dependency for cross-host signaling (development scaffolding only)
- Optional Aya loader path under `--features ebpf` with graceful fallback
- Source-level dry-run audit script: `python3 scripts/dry_run_audit.py`
- **Safe by default (established 2026-11-10):** dry-run is the default mode — with no flags the agent watches, scores, and reports without touching a process. Live enforcement requires an explicit `--live` flag, prints a warning banner, and waits 3 seconds before the first cycle. `--help` / `-h` prints usage and exits without starting; unknown flags are rejected the same way (`src/cli.rs`, unit-tested)
- Archived research scoring candidates under `docs/archive/` (versions 05/06; version 06 merged into the active engine 2026-10-04, archive retained for provenance)
- **File telemetry (added 2026-11-18):** userspace inotify watcher (`src/filewatch.rs`) populates the scorer's entropy, write-velocity, and rename-burst fields; attributed bursts bridge into the telemetry score and tag T1486 from behavior, unattributed bursts are recorded as host-level anomalies with no PID. Verified against the FBI Gootloader FLASH (CC-111626-MW) synthetic test: a plain-named realistic encryptor scored 9 (was 2 before). fanotify is unavailable in this environment, so per-process attribution relies on /proc corroboration.

## Not established yet

- Validated behavioral-detection benchmarks or false-positive rates (a first benign-workload review ran 2026-11-18 — cargo build, bulk copy, tar extract, backup renames: zero process flags, bursts recorded as host-level anomalies; broader corpora still open)
- Production host isolation, session revocation, or network quarantine behavior (the scoring model recommends them; the engine records the recommendation and holds for human authorization — it does not perform them)
- Reproducible in-repo BPF object / CI artifact for the kernel path
- LSM deny path and measured end-to-end containment timing
- Rich file-telemetry population of the scoring model via the kernel path (entropy, write velocity, rename bursts at true per-process attribution); the userspace inotify path now populates those fields with /proc-corroborated attribution, but a burst with no corroborating process stays a host-level anomaly, and a sleep-paced renamer that moves no bytes is visible but not attributable

## Suggested next engineering steps

1. ~~Keep dry-run / log-only as the default posture for any demo path~~ — done 2026-11-10: dry-run is the default, `--live` is explicit opt-in with a banner and 3-second pause
2. ~~Populate the merged scoring model from real file telemetry (eBPF path) instead of name/pressure bridges~~ — userspace part done 2026-11-18 (`src/filewatch.rs`, inotify + /proc corroboration); eBPF object now builds in-repo (2026-11-18, `ahr-ebpf.o`, 3,552 bytes, nightly 1.102.0 + bpf-linker 0.13.0) but cannot load in this container (BPF syscalls blocked, EPERM) — load/attach unproven, needs a real host
3. Write at least one integration test that exercises detection without mutating processes
4. ~~False-positive review of the merged scorer against benign process corpora~~ — first pass done 2026-11-18 (`scripts/false-positive-review/`, 4 workloads, 0 process flags); broader corpora still open
5. Treat kernel/eBPF work as optional and secondary until userspace safety rails are solid

## Run (prototype)

```bash
git clone https://github.com/Immaculate1022/AHR-Endpoint.git
cd AHR-Endpoint
cargo build --release
RUST_LOG=info ./target/release/ahr-endpoint --dry-run --once

# safety audit (does not launch the agent)
python3 scripts/dry_run_audit.py

# live enforcement (explicit opt-in only; isolated test environment only)
RUST_LOG=info ./target/release/ahr-endpoint --live --once

# optional kernel path (Linux only; requires privileges and toolchain)
cargo build --release --features ebpf
bash scripts/setup_ebpf.sh
sudo RUST_LOG=info ./target/release/ahr-endpoint --live
```

Exercise only in an isolated test environment. Do not point this agent at production endpoints until detection thresholds, response policy, audit trail, and rollback behavior have been reviewed.

## Related

- [README](README.md) — primary public description and prototype boundary
- [PegaConstellation Hub STATUS](https://github.com/Immaculate1022/pegaconstellation-hub/blob/main/STATUS.md)
- [docs/archive/](docs/archive/) — unmerged research candidates

---

*Part of the Infinite Optical Fabric / PegaConstellation research constellation.*
