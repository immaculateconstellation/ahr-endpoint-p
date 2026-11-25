//! AHR-Endpoint agent — Adaptive Hollow Reflector
//!
//! Userspace detection + merged telemetry scoring + graduated enforcement.
//! Optional eBPF kernel path via `--features ebpf` + compiled object.
//!
//! Safe by default: with no flags the agent runs in **dry-run** mode,
//! evaluating detections and reporting intended actions without writing
//! eBPF state, mutating processes, or publishing invariants. Live
//! enforcement happens ONLY with an explicit `--live` flag, after a
//! warning banner and a 3-second pause. `--help` / `-h` prints usage
//! and exits without starting the agent. Every decision — dry-run or
//! live — is written to the structured audit trail (`crate::audit`).
//! Privilege-escalated recommendations from the scoring model are held
//! for human authorization by `crate::policy`.

mod action;
mod audit;
mod cli;
mod decoy;
mod detection;
mod ebpf_loader;
mod enforcement;
mod filewatch;
mod hollow;
mod honeytoken;
mod policy;
mod probe;
mod quarantine;
mod sentinel;

#[cfg(test)]
mod integration_tests;

use cli::{Mode, ParseOutcome};
use detection::{detect_ransomware_behavior, FileHollow};
use ebpf_loader::load_optional;
use enforcement::{Action, EnforcementController};
use log::{error, info, warn};
use nats::Options;
use std::time::Duration;
use tokio::time::sleep;

async fn publish_invariant(
    hollow: &FileHollow,
    action: Action,
    decision: &policy::Decision,
    nc: &nats::Connection,
) {
    let payload = serde_json::json!({
        "pid": hollow.pid,
        "risk": decision.effective_risk,
        "snapshot_risk": decision.snapshot_risk,
        "scored_risk": decision.scored_risk,
        "process_hash": hollow.process_hash,
        "process_name": hollow.process_name,
        "action": action as u8,
        "recommended": format!("{:?}", decision.recommended),
        "requires_human_review": decision.requires_human_review,
        "reasons": decision.reasons,
        "invariant": "KILL_TREE",
        "ttl_secs": 60,
    });
    if let Err(e) = nc.publish("ahr.invariants", payload.to_string()) {
        error!("Failed to publish invariant: {}", e);
    } else {
        info!("Invariant published via NATS (<2s target)");
    }
}

/// Run one one-shot command and return its exit code:
/// 0 = done / release / credible, 3 = hold / not-credible, 1 = error,
/// 2 = bad request (unknown decoy kind).
fn run_command(command: &cli::Command, dry_run: bool) -> i32 {
    match command {
        cli::Command::QuarantineScan(path) => match quarantine::verdict(path) {
            Some(v) => {
                println!(
                    "verdict: {} — {}",
                    if v.pass { "release" } else { "hold" },
                    v.reason
                );
                println!(
                    "  size={} sampled={} head_entropy={:.2} sample_entropy={:.2} magic={:02x?}",
                    v.report.size,
                    v.report.sampled_bytes,
                    v.report.head_entropy,
                    v.report.sample_entropy,
                    v.report.magic
                );
                if v.pass {
                    0
                } else {
                    3
                }
            }
            None => {
                eprintln!("quarantine-scan: cannot read {}", path.display());
                1
            }
        },
        cli::Command::EmbedToken(path) => match honeytoken::embed_token(path, None, false, "manual")
        {
            Ok(id) => {
                println!("token: {}", id);
                0
            }
            Err(e) => {
                eprintln!("embed-token: {}", e);
                1
            }
        },
        cli::Command::MakeDecoy { kind, dir } => match decoy::generate(kind, dir) {
            Ok((path, token)) => {
                println!("decoy: {} token: {}", path.display(), token);
                0
            }
            Err(e) => {
                eprintln!("make-decoy: {}", e);
                2
            }
        },
        cli::Command::Probe { destination, file } => match probe::probe(destination, file, dry_run)
        {
            Ok(out) => {
                println!(
                    "probe: {} — {}",
                    if out.credible { "credible" } else { "not-credible" },
                    out.reason
                );
                if out.credible {
                    0
                } else {
                    3
                }
            }
            Err(e) => {
                eprintln!("probe: {}", e);
                1
            }
        },
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    // Command-line parsing is safe-by-default: no flags means dry-run,
    // `--live` is the only way into enforcement, and `--help` / unknown
    // flags exit before the agent loop can start. See `crate::cli`.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match cli::parse_args(&args) {
        Ok(ParseOutcome::Run(parsed)) => parsed,
        Ok(ParseOutcome::Help) => {
            println!("{}", cli::USAGE);
            return;
        }
        Err(e) => {
            eprintln!("ahr-endpoint: {e}\n");
            eprintln!("{}", cli::USAGE);
            std::process::exit(2);
        }
    };
    let dry_run = parsed.mode == Mode::DryRun;
    let once = parsed.once;

    // One-shot commands act, print the result, and exit — no agent
    // loop, no live banner. They are file operations the user asked
    // for, so the dry-run default does not gate them.
    if let Some(command) = parsed.command {
        std::process::exit(run_command(&command, dry_run));
    }

    info!("🚀 Adaptive Hollow Reflector Endpoint Agent starting...");
    info!("   Graduated response: Soft → Medium → Kill");
    if dry_run {
        info!("   DRY-RUN: no eBPF writes, process signals, or NATS invariants will be emitted");
    } else {
        // Loud live-mode warning, then a 3-second pause: enforcement is
        // real from the first cycle, so anyone who started this by
        // mistake gets a chance to stop it with Ctrl-C first.
        eprintln!();
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        eprintln!("!!  LIVE MODE — enforcement active: matching processes   !!");
        eprintln!("!!  WILL be suspended/killed. Dry-run is the default;  !!");
        eprintln!("!!  you asked for live with --live. Starting in 3s —  !!");
        eprintln!("!!  press Ctrl-C now to stop.                          !!");
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        eprintln!();
        warn!("LIVE MODE — enforcement active: matching processes WILL be suspended/killed");
        std::thread::sleep(Duration::from_secs(3));
    }

    // File telemetry first: the I/O baseline is taken here so the first
    // detection cycle's delta covers the ~400 ms warm-up interval below.
    // A failure only disables file signals; name/pressure detection
    // keeps working (see crate::filewatch).
    filewatch::init();

    // Quarantine buffer + canary watch, when configured (flag wins
    // over env for the quarantine dir). Unconfigured means disabled:
    // the agent runs without quarantine or token-use reporting.
    if let Some(dir) = &parsed.quarantine_dir {
        quarantine::init_with(dir.clone());
    } else {
        quarantine::init();
    }
    honeytoken::init_canary_watch();

    // Warm up the shared process snapshot so the first detection cycle
    // already sees a valid CPU delta (see detection::warm_up_detection).
    // One-time ~400 ms cost at startup, in dry-run and live alike.
    detection::warm_up_detection();

    let mut controller = EnforcementController::new();
    let mut ebpf = if dry_run { None } else { load_optional() };

    let nc = if dry_run {
        None
    } else {
        match Options::new().connect("nats://localhost:4222") {
            Ok(c) => {
                info!("Connected to NATS cluster for global immunization.");
                Some(c)
            }
            Err(e) => {
                warn!("NATS not available (standalone mode): {}", e);
                None
            }
        }
    };

    loop {
        // Quarantine buffer: scan new arrivals, release or hold.
        // Canary watch: drain token-use events (each hit is already
        // written to the audit trail by the watcher).
        let _ = quarantine::cycle(dry_run);
        let _ = honeytoken::cycle();

        let expired = controller.sweep();
        if let Some(ref mut enf) = ebpf {
            for pid in expired {
                let _ = enf.clear_action(pid);
            }
        }

        // Detection order: name/pressure first, then file activity.
        // A file-activity snapshot is a real process (attributed by the
        // watcher); an unattributed burst is reported below as a
        // host-level anomaly, never as an invented process.
        let hollow =
            detect_ransomware_behavior().or_else(detection::detect_file_activity);
        if let Some(hollow) = hollow {
            // Score with the merged telemetry model and let policy combine
            // both scorers into one auditable decision.
            let scored = hollow.assess();
            let decision = policy::decide(&hollow, &scored);
            let action = decision.executable;
            let ttl = 60u64;

            if dry_run {
                info!(
                    "DRY-RUN would flag PID {} action={:?} ttl={} snapshot_risk={} scored_risk={} effective_risk={} recommended={:?} human_review={} reasons={:?}",
                    hollow.pid,
                    action,
                    ttl,
                    decision.snapshot_risk,
                    decision.scored_risk,
                    decision.effective_risk,
                    decision.recommended,
                    decision.requires_human_review,
                    decision.reasons
                );
            } else {
                // Moving-target defense: jitter dispatch timing so response
                // latency can't be used to fingerprint risk thresholds.
                // Detection stays deterministic; only dispatch timing varies.
                sleep(detection::dispatch_delay_for(
                    decision.effective_risk,
                    hollow.is_decoy,
                ))
                .await;
                controller.flag(
                    hollow.pid,
                    action,
                    ttl,
                    &format!(
                        "risk={} name={} reasons={}",
                        decision.effective_risk,
                        hollow.process_name,
                        decision.reasons.join("; ")
                    ),
                );
            }

            if !dry_run {
                if let Some(ref mut enf) = ebpf {
                    if let Err(e) = enf.set_action(hollow.pid, action.as_u8()) {
                        warn!("eBPF map update failed: {e}");
                    }
                }
            }

            if dry_run {
                let record = audit::build_record(
                    hollow.pid,
                    &hollow.process_name,
                    &hollow.process_hash,
                    scored.anomaly_score,
                    &decision,
                    true,
                    false,
                );
                audit::emit(&record);
                info!(
                    "DRY-RUN decision: PID {} action={:?} risk={} process={}",
                    hollow.pid, action, decision.effective_risk, hollow.process_name
                );
            } else {
                let ok = controller.apply_userspace(hollow.pid, action);
                if ok {
                    warn!(
                        "Containment activated — PID {} action={:?} (Patient Zero)",
                        hollow.pid, action
                    );
                }
                if decision.requires_human_review {
                    warn!(
                        "Human review required: PID {} recommendation {:?} held at {:?}",
                        hollow.pid, decision.recommended, action
                    );
                }

                let record = audit::build_record(
                    hollow.pid,
                    &hollow.process_name,
                    &hollow.process_hash,
                    scored.anomaly_score,
                    &decision,
                    false,
                    ok,
                );
                audit::emit(&record);

                // Sentinel X evidence stream: local sink first (works
                // without a broker), then NATS when connected.
                let event = sentinel::build_event(
                    hollow.pid,
                    &hollow.process_name,
                    &scored,
                    &decision,
                    ok,
                );
                sentinel::write_sink(&event);

                if let Some(ref conn) = nc {
                    publish_invariant(&hollow, action, &decision, conn).await;
                    sentinel::publish_evidence(conn, &event);
                }
            }
        } else if filewatch::burst_active() {
            // Host-level file-activity anomaly: a burst is active in the
            // watched trees but no process corroborated attribution.
            // Record the measured rates with no PID — never invent one.
            let sig = filewatch::signals();
            let record = audit::build_file_anomaly(
                None,
                filewatch::watch_paths(),
                sig.renames,
                sig.writes,
                sig.entropy_delta,
                dry_run,
            );
            audit::emit_file_anomaly(&record);
            info!(
                "DRY-RUN file-activity anomaly (unattributed): renames={} writes={} max_entropy={:.2} watch={:?}",
                sig.renames,
                sig.writes,
                sig.entropy_delta,
                filewatch::watch_paths()
            );
        }

        if once {
            info!("Single-cycle run complete");
            break;
        }
        sleep(Duration::from_secs(3)).await;
    }
}
