# AHR vs Gootloader — synthetic behavior test

FBI FLASH CC-111626-MW (16 November 2026), "Gootloader Malware Using
SEO Poisoning and Compromised Websites to Gain Initial Access"
(IC3 PDF: https://www.ic3.gov/CSA/2026/261116.pdf).

## Boundary

Gootloader is a **Windows** initial-access framework; AHR-Endpoint is a
**Linux** userspace agent. **No real Gootloader is used, fetched, or run.**
This test simulates the endpoint behaviors AHR actually watches with
benign stand-ins, in AHR **dry-run** mode. Nothing is enforced, no
process is touched by AHR, and all sim processes are killed afterward.
This is a test of which Gootloader behaviors fall inside AHR's current
detection surface — not a test of "AHR detects Gootloader."

## Run

```bash
./scripts/gootloader-test/run.sh
```

Each run uses a fresh scratch dir under `/tmp` (printed at the end);
audit JSONL records land in its `logs/` directory.

## Scenarios

| Case | Sim | Expected (v0.3.0 + file telemetry) |
|---|---|---|
| S0 baseline | none | clean |
| S1 | `pwsh` at 100% CPU | flagged, risk 7 (T1059) |
| S2 | `encryptor-sim` at 100% CPU | flagged, risk 9 (T1486) |
| S3 | `pwsh-chain` parent + 2 descendant levels | flagged, risk 7 |
| S4 | benign `worker-sim` at 100% CPU | clean (name gate) |
| S5 | `pwsh-idle` sleeping | clean (pressure gate) |
| S6 | mass renames, plain `python3` name, low CPU | host-level file-activity anomaly, unattributed |
| S7 | realistic encryptor (read → write urandom → rename), plain `python3` name | flagged via file telemetry, scored 9 |

Full scorecard: `~/workspace/goals/ahr-endpoint-hardened-realtime-defense/files/ahr-vs-gootloader-test-2026-11-18.md`.
File-telemetry fix note: `.../ahr-file-telemetry-fix-2026-11-18.md`.
