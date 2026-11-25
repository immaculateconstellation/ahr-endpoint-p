# AHR false-positive review — benign workloads

The 2026-11-18 file-telemetry fix made AHR sensitive to bulk file
activity. These workloads measure whether ordinary work trips it.

## Run

```bash
./scripts/false-positive-review/run.sh
```

Each run uses a fresh scratch dir under `/tmp` (printed at the end);
audit JSONL records land in its `logs/` directory.

## Cases (all benign, all dry-run)

| Case | Workload | What it stresses |
|---|---|---|
| B1 cargo-build | `cargo clean` + `cargo build` loop on a 60-module crate | writes + renames + compiler-output entropy |
| B2 bulk-copy | `cp -r` of a 150-file mostly-text tree, looped | write velocity, low entropy, no renames |
| B3 tar-extract | extract a tarball of the tree, looped | write velocity + creates |
| B4 backup-renames | copy files, rename previous copy to `.bak`, looped | write + rename, low entropy — the encryptor shape minus entropy |

## How to read the result

A **clean** case means no audit record. A **flag** means AHR would
have acted in live mode — note the snapshot/scored risk, the reasons,
and the executable action, and judge whether the workload deserved it.
A flag on B2/B3/B4 is a false positive by construction (these are
ordinary operations); a flag on B1 needs a closer look at which
process was blamed (cargo vs rustc) and why.
