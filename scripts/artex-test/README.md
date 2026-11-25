# AHR vs ARTEX — synthetic behavior test

FBI FLASH-20261113-001, "Threat Overview of ARTEX Autonomous Penetration
Testing Framework" (13 Nov 2026, TLP:CLEAR). Same pattern as
`../gootloader-test/`: benign simulations in AHR dry-run mode only.
No ARTEX code was fetched, built, or run.

## Sims (all benign, loopback/scratch only)

- `exfil.py` — S7-style: read → write high-entropy bytes → rename,
  rotating over 8 destinations so disk stays bounded.
- `credsweep.py` — read-only sweep of 120 dummy credential-like files
  (fake .pem / id_rsa / .env / AWS credentials).
- `listener.py` — dummy TCP listener on 127.0.0.1, accepts and closes.
- `spray.py` — rapid connection attempts to the dummy listener plus a
  short-lived `sleep` child every 15 attempts (password-spray shape).
- `beacon.py` — periodic outbound connection to the dummy listener
  every 2 s (C2 beacon shape).
- `chain.py` — compressed chain: cred reads (2 s) → hot `pwsh` (3 s) →
  exfil (4 s), then exits.
- `freshchain.py` — exfil pattern for ~4 s inside a subdirectory created
  after AHR started, then exits (new-dir race + attribution window).

## Cases

| Case | Sim | FLASH behavior |
|---|---|---|
| A0 | none | baseline |
| A1 | `artex-agent` spinning 100% CPU | ARTEX agent process by name |
| A2 | spray sim + short-lived children | password spraying / sequential enumeration |
| A3 | read-only credential sweep | T1552.001 / T1555 / T1005 credential access |
| A4 | exfil sim, plain name `python3` | T1074 / T1005 staging + exfil prep |
| A5 | C2 beacon to local listener | T1071.001 / T1090 / T1572 |
| A6a | compressed chain, watched dir | "under 3 hours" — fast chain, known dir |
| A6b | fast chain, fresh subdir | "under 3 hours" — fast chain, new dir |
| A7 | FP review harness (B1–B4) | 0 process flags expected |

## Run

```sh
./scripts/artex-test/run.sh
```

Scratch lives under a `mktemp` dir in /tmp and is removed on exit
(`trap ... rm -rf`). Audit records print inline per case; full output
is tee'd to `last-run.log`. Report:
`~/workspace/goals/ahr-endpoint-hardened-realtime-defense/files/ahr-vs-artex-test-2026-11-18.md`.
