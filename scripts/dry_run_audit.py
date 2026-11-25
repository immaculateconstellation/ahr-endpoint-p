#!/usr/bin/env python3
"""Static safety audit for the AHR dry-run path.

This script never imports or executes the AHR agent and never touches a process,
eBPF map, NATS server, or host state. It checks that the source advertises and
guards the dry-run controls, then emits a machine-readable report.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "src" / "main.rs"
CLI = ROOT / "src" / "cli.rs"
ARCHIVE = ROOT / "docs" / "archive"

source = MAIN.read_text(encoding="utf-8")
cli_source = CLI.read_text(encoding="utf-8")
checks = {
    # Flag parsing lives in src/cli.rs (safe-by-default parser, 2026-11-10):
    # dry-run is the default, --live is explicit opt-in, --help exits
    # before the agent starts, unknown flags are refused.
    "dry_run_flag_present": '"--dry-run"' in cli_source,
    "single_cycle_flag_present": '"--once"' in cli_source,
    "live_flag_present": '"--live"' in cli_source,
    "help_flag_present": '"--help"' in cli_source,
    "default_mode_is_dry_run": "Mode::DryRun" in cli_source
    and "parsed.mode = if live { Mode::Live } else { Mode::DryRun }" in cli_source,
    "dry_run_disables_ebpf_loader": "if dry_run { None } else { load_optional() }" in source,
    "dry_run_disables_nats_connection": "let nc = if dry_run" in source,
    "enforcement_guard_present": "if !dry_run" in source,
    "userspace_apply_inside_non_dry_branch": source.count("controller.apply_userspace") == 1 and source.find("controller.apply_userspace") > source.find("if dry_run"),
    "nats_publish_inside_non_dry_branch": source.count("publish_invariant") == 2 and source.find("publish_invariant(&hollow") > source.find("if dry_run"),
    "archive_contains_candidate_modules": all((ARCHIVE / name).exists() for name in ("Pasted_content_05_hollow.rs", "Pasted_content_06_hollow.rs")),
}

report = {
    "mode": "static-dry-run-audit",
    "enforcement_executed": False,
    "external_connections_attempted": False,
    "active_engine": "src/main.rs",
    "archive": str(ARCHIVE.relative_to(ROOT)),
    "checks": checks,
    "passed": all(checks.values()),
    "notes": [
        "This audit verifies source-level safety gates; it is not a behavioral detection benchmark.",
        "This script does not compile or launch Rust; cargo fmt, cargo check, and cargo test were verified separately at the published commit.",
        "Archived scoring candidates are retained for provenance; the version 06 candidate was merged into src/hollow.rs on 2026-10-04 with in-crate tests, dry-run behavior, audit logging, and human-authorization gates.",
    ],
}
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if report["passed"] else 1)
