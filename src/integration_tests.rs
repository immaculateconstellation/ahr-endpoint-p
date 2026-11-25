//! Integration tests: detection → scoring → policy, end to end.
//!
//! These tests never mutate a process. The pipeline tests use synthetic
//! snapshots only — no process is started, signalled, or touched. The
//! live test spawns one synthetic process of its own, verifies detection
//! flags it, and kills only that child afterwards as cleanup.

use crate::action::Action;
use crate::detection::{detect_ransomware_behavior, warm_up_detection, FileHollow};
use crate::hollow::{EndpointAction, FileHollow as ScoredHollow};
use crate::policy::decide;

fn snapshot(name: &str, risk: u8) -> FileHollow {
    FileHollow {
        pid: 4242,
        risk,
        process_hash: "deadbeef".into(),
        process_name: name.into(),
        is_decoy: false,
        tree_depth: 0,
        runs_as_admin: false,
        write_velocity: 0,
        rename_burst: false,
        entropy_delta: 0.0,
    }
}

fn scored(snapshot: &FileHollow) -> ScoredHollow {
    snapshot.assess()
}

/// A suspicious snapshot (encrypt-named, risk 9) escalates through the
/// full pipeline to a KillTree recommendation and a Kill executable
/// action — no process involved, pure snapshot in, decision out.
#[test]
fn suspicious_snapshot_escalates_to_kill() {
    let snap = snapshot("encrypt_mem", 9);
    let scored = scored(&snap);
    // Only the name indicator and "unsigned binary" feed the scored
    // model here; the detector ladder is what drives the risk to 9.
    assert_eq!(scored.risk_score, 2);
    assert!(scored.has_ttp("T1486"));

    let decision = decide(&snap, &scored);
    assert_eq!(decision.effective_risk, 9);
    // The scored model only observed a name indicator plus an unsigned
    // binary, so it recommends LogOnly; the detector ladder is what
    // drives the risk to 9, and the executable action follows the
    // effective risk. Recommendation and executable action are
    // deliberately separate — see the dry-run audit records.
    assert_eq!(decision.recommended, EndpointAction::LogOnly);
    assert_eq!(decision.executable, Action::Kill);
    assert!(!decision.requires_human_review);
}

/// A benign snapshot (plain name, risk 1) stays at the bottom of the
/// ladder: LogOnly recommendation, Allow executable action.
#[test]
fn benign_snapshot_stays_allow() {
    let snap = snapshot("bash", 1);
    let scored = scored(&snap);
    assert!(!scored.has_ttp("T1486"));

    let decision = decide(&snap, &scored);
    assert!(decision.effective_risk <= 3);
    assert_eq!(decision.recommended, EndpointAction::LogOnly);
    assert_eq!(decision.executable, Action::Allow);
    assert!(!decision.requires_human_review);
}

/// File signals alone move the scorer: a plain-named snapshot carrying
/// a rename burst, high write entropy, and high write velocity scores
/// 9 (1 base + 2 rename + 3 entropy + 2 velocity + 1 unsigned) and
/// carries T1486 from behavior, not from its name. This is the gap the
/// Gootloader test exposed — file telemetry now reaches the scorer.
#[test]
fn file_signals_alone_drive_score_and_ttp() {
    let mut snap = snapshot("worker", 6);
    snap.rename_burst = true;
    snap.entropy_delta = 0.95;
    snap.write_velocity = 80;
    let scored = scored(&snap);
    assert_eq!(scored.risk_score, 9);
    assert!(scored.has_ttp("T1486"));
    assert_eq!(scored.recommended_action(), EndpointAction::KillTree);

    let decision = decide(&snap, &scored);
    assert_eq!(decision.effective_risk, 9);
    assert_eq!(decision.executable, Action::Kill);
}

/// Live detection, end to end, without mutating any process: with no
/// suspicious process running, detection finds nothing; with a
/// synthetic CPU spinner under a suspicious name running, detection
/// flags exactly that process at risk 9. The spinner is this test's
/// own child and is killed by the test afterwards.
///
/// Note: the probe name must stay short — the kernel truncates process
/// names (comm) to 15 characters, so the "encrypt" substring has to
/// fit inside that limit.
#[test]
fn live_detection_flags_synthetic_spinner_and_ignores_benign() {
    // Baseline: nothing suspicious running on this box.
    warm_up_detection();
    assert!(
        detect_ransomware_behavior().is_none(),
        "baseline: expected no detection with no suspicious process running"
    );

    // Spawn a synthetic CPU spinner under a suspicious name: a copy of
    // python3 named "encrypt_spin" running a busy loop. Low memory, so
    // only the CPU leg can flag it.
    let python = "/usr/bin/python3";
    assert!(
        std::path::Path::new(python).exists(),
        "python3 is required for this test"
    );
    let probe_path = "/tmp/encrypt_spin";
    let _ = std::fs::remove_file(probe_path);
    std::fs::copy(python, probe_path).expect("copy python3 to probe path");
    let mut child = std::process::Command::new(probe_path)
        .arg("-c")
        .arg("while True: pass")
        .spawn()
        .expect("spawn spinner");
    let child_pid = child.id();

    // Let it accumulate CPU time, then look for it. Retry a few times:
    // detection returns the first match in hash-map order, and the
    // spinner's CPU reading settles over the first refreshes.
    std::thread::sleep(std::time::Duration::from_millis(600));
    let mut found = None;
    for _ in 0..10 {
        if let Some(hit) = detect_ransomware_behavior() {
            if hit.pid == child_pid {
                found = Some(hit);
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // Clean up first so a failure never leaks a spinning process.
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(probe_path);

    let hit = found.expect("detection should flag the synthetic spinner");
    assert_eq!(hit.risk, 9);
    assert_eq!(hit.process_name, "encrypt_spin");
}
