//! Pre-send credibility probe — the token goes first.
//!
//! Before a file leaves, its honeytoken is sent ahead of it: the file
//! is sealed with its token, the destination is checked against the
//! allowlist (when one is configured), and then the token is watched
//! for a window. If the token is used unexpectedly during that window
//! — opened or read by anyone — the destination is not credible and
//! the real file does not go. If the window stays clean, the file is
//! released.
//!
//! The check is fail-closed: any access during the window counts,
//! including an access whose reader is already gone when attribution
//! runs (the inotify event itself is the evidence). The probe treats
//! the AHR agent's own sampling as self-access (exe `ahr-endpoint`)
//! and ignores it; anything else is use. Run probes on files outside
//! the agent's filewatch trees when the agent loop is running, so its
//! entropy sampling cannot trip the window.
//!
//! Honest limits: the probe watches the *token file on this host* for
//! the window — it cannot see what happens to the token after it
//! leaves, and it cannot prove a destination is trustworthy, only
//! that nothing unexpected touched the token while the probe watched.
//! A clean window is a clean window, not a guarantee.

use crate::audit;
use crate::honeytoken;
use log::{info, warn};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// Default probe window (seconds) when `AHR_PROBE_WINDOW_SECS` is unset.
pub const DEFAULT_WINDOW_SECS: u64 = 10;

/// The outcome of one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub probe_id: String,
    pub token_id: String,
    pub credible: bool,
    pub reason: String,
}

/// Run a pre-send probe with explicit parameters (registry path and
/// allowlist). `allowlist` is None when no allowlist is configured —
/// any destination may then be probed.
pub fn probe_with(
    destination: &str,
    file: &Path,
    window_secs: u64,
    dry_run: bool,
    registry: &Path,
    allowlist: Option<&[String]>,
) -> Result<ProbeOutcome, String> {
    if window_secs == 0 {
        return Err("probe window must be > 0 seconds".to_string());
    }
    if !file.is_file() {
        return Err(format!("probe target is not a file: {}", file.display()));
    }
    let probe_id = format!("probe-{}", &honeytoken::new_token_id()[..12]);

    // 1. Seal: no file leaves without a token.
    let token_id = honeytoken::embed_token_at(
        file,
        registry,
        Some(destination.to_string()),
        false,
        "probe",
    )?;
    honeytoken::set_destination_at(registry, &token_id, destination);

    // 2. Allowlist (when configured): an unlisted destination is not
    // credible without ever opening the window.
    if let Some(list) = allowlist {
        if !list.iter().any(|d| d == destination) {
            let reason = format!("destination '{}' is not on the probe allowlist", destination);
            emit_verdict(&probe_id, &token_id, file, destination, false, &reason, window_secs, dry_run);
            return Ok(ProbeOutcome {
                probe_id,
                token_id,
                credible: false,
                reason,
            });
        }
    }

    // 3. Watch the token file for the window. Any open/read by anyone
    // but the AHR agent itself is unexpected use.
    let parent = file.parent().ok_or_else(|| {
        format!("probe target has no parent directory: {}", file.display())
    })?;
    let file_name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| format!("probe target has no file name: {}", file.display()))?;
    // SAFETY: inotify_init1 non-blocking + close-on-exec; no
    // privileges required.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "probe watch failed (inotify_init1): {}",
            std::io::Error::last_os_error()
        ));
    }
    struct FdGuard(i32);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            if self.0 >= 0 {
                unsafe { libc::close(self.0) };
            }
        }
    }
    let _guard = FdGuard(fd);
    let cpath = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| "probe directory path contains NUL".to_string())?;
    let mask = (libc::IN_OPEN | libc::IN_ACCESS) as u32;
    let wd = unsafe { libc::inotify_add_watch(fd, cpath.as_ptr(), mask) };
    if wd < 0 {
        return Err(format!(
            "probe watch failed (inotify_add_watch on {}): {}",
            parent.display(),
            std::io::Error::last_os_error()
        ));
    }
    info!(
        "probe {} watching {} for {}s (destination '{}')",
        probe_id,
        file.display(),
        window_secs,
        destination
    );
    let deadline = Instant::now() + Duration::from_secs(window_secs);
    let mut buf = [0u8; 65536];
    loop {
        // Drain whatever the kernel queued.
        loop {
            // SAFETY: fd is a valid non-blocking inotify fd; buf is ours.
            let n = unsafe {
                libc::read(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let mut off = 0usize;
            while off + 16 <= n {
                let ev_mask =
                    u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
                let len =
                    u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
                let name_bytes = &buf[off + 16..(off + 16 + len).min(n)];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(len);
                let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
                off += 16 + len;
                let is_access = ev_mask & ((libc::IN_OPEN as u32) | (libc::IN_ACCESS as u32)) != 0;
                if !is_access || name != file_name {
                    continue;
                }
                // Attribute the reader when it is still visible.
                // The AHR agent's own sampling is self-access, not use.
                if let Some((pid, exe)) = honeytoken::find_reader(file) {
                    if exe == "ahr-endpoint" {
                        continue;
                    }
                    let reason = format!(
                        "token used during probe window by PID {} ({})",
                        pid, exe
                    );
                    emit_verdict(&probe_id, &token_id, file, destination, false, &reason, window_secs, dry_run);
                    return Ok(ProbeOutcome {
                        probe_id,
                        token_id,
                        credible: false,
                        reason,
                    });
                }
                // Unattributed access: the event itself proves the
                // token file was opened during the window.
                let reason =
                    "token file was opened during the probe window (reader already gone)"
                        .to_string();
                emit_verdict(&probe_id, &token_id, file, destination, false, &reason, window_secs, dry_run);
                return Ok(ProbeOutcome {
                    probe_id,
                    token_id,
                    credible: false,
                    reason,
                });
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let reason = format!(
        "no unexpected use of the token during the {}s window",
        window_secs
    );
    emit_verdict(&probe_id, &token_id, file, destination, true, &reason, window_secs, dry_run);
    Ok(ProbeOutcome {
        probe_id,
        token_id,
        credible: true,
        reason,
    })
}

fn emit_verdict(
    probe_id: &str,
    token_id: &str,
    file: &Path,
    destination: &str,
    credible: bool,
    reason: &str,
    window_secs: u64,
    dry_run: bool,
) {
    let record = audit::build_probe(
        probe_id,
        token_id,
        &file.to_string_lossy(),
        destination,
        if credible { "credible" } else { "not-credible" },
        reason.to_string(),
        window_secs,
        dry_run,
    );
    audit::emit_probe(&record);
    if credible {
        info!("probe {} credible: {} -> {}", probe_id, file.display(), destination);
    } else {
        warn!(
            "probe {} NOT credible: {} -> {} ({})",
            probe_id,
            file.display(),
            destination,
            reason
        );
    }
}

/// Probe allowlist from `AHR_PROBE_ALLOWLIST` (colon-separated).
/// None when unset or empty — any destination may then be probed.
pub fn allowlist_from_env() -> Option<Vec<String>> {
    std::env::var("AHR_PROBE_ALLOWLIST")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.split(':')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
}

/// Probe window from `AHR_PROBE_WINDOW_SECS`, else the default.
pub fn window_from_env() -> u64 {
    std::env::var("AHR_PROBE_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|w| *w > 0)
        .unwrap_or(DEFAULT_WINDOW_SECS)
}

/// Run a pre-send probe with env configuration (registry, allowlist,
/// window).
pub fn probe(
    destination: &str,
    file: &Path,
    dry_run: bool,
) -> Result<ProbeOutcome, String> {
    let registry = honeytoken::registry_path();
    let allowlist = allowlist_from_env();
    let window = window_from_env();
    probe_with(
        destination,
        file,
        window,
        dry_run,
        &registry,
        allowlist.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    fn test_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(name);
        let _ = fs::create_dir_all(&d);
        d
    }

    #[test]
    fn probe_clean_window_is_credible() {
        let dir = test_dir("ahr-probe-clean");
        let reg = dir.join("registry.json");
        let p = dir.join("report.txt");
        fs::write(&p, b"quarterly report\n").unwrap();
        let out = probe_with("alice@example.com", &p, 1, true, &reg, None).unwrap();
        assert!(out.credible, "clean window should be credible: {}", out.reason);
        assert!(!out.token_id.is_empty());
        // The file was sealed on the way through.
        assert_eq!(honeytoken::file_token_at(&reg, &p), Some(out.token_id));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_allowlist_blocks_unknown_destination() {
        let dir = test_dir("ahr-probe-allowlist");
        let reg = dir.join("registry.json");
        let p = dir.join("report.txt");
        fs::write(&p, b"quarterly report\n").unwrap();
        let allow = vec!["alice@example.com".to_string()];
        let out = probe_with("mallory@example.com", &p, 1, true, &reg, Some(&allow)).unwrap();
        assert!(!out.credible, "unlisted destination must not be credible");
        assert!(out.reason.contains("allowlist"), "reason: {}", out.reason);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_detects_foreign_open() {
        let dir = test_dir("ahr-probe-foreign");
        let reg = dir.join("registry.json");
        let p = dir.join("report.txt");
        fs::write(&p, b"quarterly report\n").unwrap();
        // A foreign reader opens the file mid-window.
        let victim = p.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            let _ = Command::new("cat").arg(&victim).output();
        });
        let out = probe_with("alice@example.com", &p, 4, true, &reg, None).unwrap();
        let _ = handle.join();
        assert!(!out.credible, "foreign open must fail the probe: {}", out.reason);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_zero_window_is_an_error() {
        let dir = test_dir("ahr-probe-zero");
        let reg = dir.join("registry.json");
        let p = dir.join("report.txt");
        fs::write(&p, b"x\n").unwrap();
        assert!(probe_with("alice@example.com", &p, 0, true, &reg, None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
