//! Structured audit logging for detection → decision → action.
//!
//! Every detection produces one JSON audit record: both risk scores, the
//! effective risk, the score reasons, the recommendation, the executable
//! action, whether a human must review the escalation, and whether the
//! record comes from a dry run. Records go to the log, and are appended as
//! JSONL to the file named by `AHR_AUDIT_LOG` when that variable is set —
//! an append-only trail a SOC (or Sentinel X) can tail in real time.

use crate::hollow::EndpointAction;
use crate::policy::Decision;
use log::info;
use serde::Serialize;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub ts_unix: u64,
    pub pid: u32,
    pub process_name: String,
    pub process_hash: String,
    pub snapshot_risk: u8,
    pub scored_risk: u8,
    pub effective_risk: u8,
    pub anomaly_score: f32,
    pub reasons: Vec<String>,
    pub recommended: String,
    pub companions: Vec<String>,
    pub executable_action: String,
    pub requires_human_review: bool,
    pub dry_run: bool,
    pub applied: bool,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn build_record(
    pid: u32,
    process_name: &str,
    process_hash: &str,
    anomaly_score: f32,
    decision: &Decision,
    dry_run: bool,
    applied: bool,
) -> AuditRecord {
    AuditRecord {
        ts_unix: now_unix(),
        pid,
        process_name: process_name.to_string(),
        process_hash: process_hash.to_string(),
        snapshot_risk: decision.snapshot_risk,
        scored_risk: decision.scored_risk,
        effective_risk: decision.effective_risk,
        anomaly_score,
        reasons: decision.reasons.clone(),
        recommended: format!("{:?}", decision.recommended),
        companions: decision
            .companions
            .iter()
            .map(|c: &EndpointAction| format!("{:?}", c))
            .collect(),
        executable_action: format!("{:?}", decision.executable),
        requires_human_review: decision.requires_human_review,
        dry_run,
        applied,
    }
}

/// Emit one audit record to the log and, when `AHR_AUDIT_LOG` is set, to
/// the append-only JSONL trail. File failures are logged, never fatal —
/// the audit trail must not take the agent down with it.
pub fn emit(record: &AuditRecord) {
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            log::error!("audit serialization failed: {}", e);
            return;
        }
    };
    info!("AUDIT {}", line);
    append_jsonl(&line);
}

/// Host-level file-activity anomaly: a burst (mass renames, write
/// velocity, high-entropy writes) is active in the watched trees, but no
/// process could be attributed — or, when `pid` is set, the burst was
/// attributed and the matching process record carries the full decision.
/// `pid` is None exactly when attribution failed; the record never
/// invents a process. Emitted in addition to (never instead of) a
/// process record when attribution succeeds.
#[derive(Debug, Serialize)]
pub struct FileAnomalyRecord {
    pub ts_unix: u64,
    pub kind: &'static str,
    pub pid: Option<u32>,
    pub watch_paths: Vec<String>,
    pub renames_in_window: u32,
    pub writes_in_window: u32,
    pub max_entropy: f32,
    pub attributed: bool,
    pub dry_run: bool,
}

pub fn build_file_anomaly(
    pid: Option<u32>,
    watch_paths: Vec<String>,
    renames: u32,
    writes: u32,
    max_entropy: f32,
    dry_run: bool,
) -> FileAnomalyRecord {
    FileAnomalyRecord {
        ts_unix: now_unix(),
        kind: "file-activity-anomaly",
        pid,
        watch_paths,
        renames_in_window: renames,
        writes_in_window: writes,
        max_entropy,
        attributed: pid.is_some(),
        dry_run,
    }
}

/// Emit one anomaly record to the log and the JSONL trail (same sink as
/// process records, same never-fatal rule).
pub fn emit_file_anomaly(record: &FileAnomalyRecord) {
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            log::error!("audit serialization failed: {}", e);
            return;
        }
    };
    info!("AUDIT {}", line);
    append_jsonl(&line);
}

/// A honeytoken fired: a token-bearing file was opened or read by a
/// process other than AHR itself. `reader_pid` is None exactly when the
/// access was observed (inotify IN_OPEN/IN_ACCESS) but no process still
/// held the file open when attribution ran — a quick open/close. The
/// event itself is the evidence; attribution is a bonus, never
/// invented. `is_decoy` marks a dummy file (the dye pack): a hit on a
/// decoy means someone is rummaging for files to take.
#[derive(Debug, Serialize)]
pub struct TokenHitRecord {
    pub ts_unix: u64,
    pub kind: &'static str,
    pub token_id: String,
    pub file: String,
    pub reader_pid: Option<u32>,
    pub reader_exe: Option<String>,
    pub is_decoy: bool,
    pub destination: Option<String>,
    pub dry_run: bool,
}

pub fn build_token_hit(
    token_id: &str,
    file: &str,
    reader_pid: Option<u32>,
    reader_exe: Option<String>,
    is_decoy: bool,
    destination: Option<String>,
    dry_run: bool,
) -> TokenHitRecord {
    TokenHitRecord {
        ts_unix: now_unix(),
        kind: "canary-hit",
        token_id: token_id.to_string(),
        file: file.to_string(),
        reader_pid,
        reader_exe,
        is_decoy,
        destination,
        dry_run,
    }
}

/// Emit one token-hit record to the log and the JSONL trail (same sink
/// as process records, same never-fatal rule).
pub fn emit_token_hit(record: &TokenHitRecord) {
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            log::error!("audit serialization failed: {}", e);
            return;
        }
    };
    info!("AUDIT {}", line);
    append_jsonl(&line);
}

/// A quarantine verdict: a staged file was sample-scanned and either
/// released into the environment or held. `reason` names the check
/// that decided it (magic match/mismatch, entropy, text plausibility).
#[derive(Debug, Serialize)]
pub struct QuarantineRecord {
    pub ts_unix: u64,
    pub kind: &'static str,
    pub file: String,
    pub verdict: &'static str,
    pub reason: String,
    pub head_entropy: f32,
    pub sample_entropy: f32,
    pub sampled_bytes: usize,
    pub dry_run: bool,
}

pub fn build_quarantine(
    file: &str,
    verdict: &'static str,
    reason: String,
    head_entropy: f32,
    sample_entropy: f32,
    sampled_bytes: usize,
    dry_run: bool,
) -> QuarantineRecord {
    QuarantineRecord {
        ts_unix: now_unix(),
        kind: "quarantine-verdict",
        file: file.to_string(),
        verdict,
        reason,
        head_entropy,
        sample_entropy,
        sampled_bytes,
        dry_run,
    }
}

/// Emit one quarantine record to the log and the JSONL trail.
pub fn emit_quarantine(record: &QuarantineRecord) {
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            log::error!("audit serialization failed: {}", e);
            return;
        }
    };
    info!("AUDIT {}", line);
    append_jsonl(&line);
}

/// A pre-send probe verdict: a token was sent ahead of a file to check
/// a destination's credibility, and the window either stayed clean
/// (credible) or the token was used unexpectedly (not credible — the
/// file does not go).
#[derive(Debug, Serialize)]
pub struct ProbeRecord {
    pub ts_unix: u64,
    pub kind: &'static str,
    pub probe_id: String,
    pub token_id: String,
    pub file: String,
    pub destination: String,
    pub verdict: &'static str,
    pub reason: String,
    pub window_secs: u64,
    pub dry_run: bool,
}

pub fn build_probe(
    probe_id: &str,
    token_id: &str,
    file: &str,
    destination: &str,
    verdict: &'static str,
    reason: String,
    window_secs: u64,
    dry_run: bool,
) -> ProbeRecord {
    ProbeRecord {
        ts_unix: now_unix(),
        kind: "probe-verdict",
        probe_id: probe_id.to_string(),
        token_id: token_id.to_string(),
        file: file.to_string(),
        destination: destination.to_string(),
        verdict,
        reason,
        window_secs,
        dry_run,
    }
}

/// Emit one probe record to the log and the JSONL trail.
pub fn emit_probe(record: &ProbeRecord) {
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            log::error!("audit serialization failed: {}", e);
            return;
        }
    };
    info!("AUDIT {}", line);
    append_jsonl(&line);
}

fn append_jsonl(line: &str) {
    if let Ok(path) = std::env::var("AHR_AUDIT_LOG") {
        if !path.is_empty() {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(mut f) => {
                    if let Err(e) = writeln!(f, "{}", line) {
                        log::error!("audit trail write failed ({}): {}", path, e);
                    }
                }
                Err(e) => log::error!("audit trail open failed ({}): {}", path, e),
            }
        }
    }
}
