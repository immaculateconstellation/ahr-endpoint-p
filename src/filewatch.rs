//! Userspace file-activity telemetry (inotify) feeding the merged scorer.
//!
//! This closes the gap the 2026-11-18 Gootloader test demonstrated: the
//! v06 scorer already had `entropy_delta`, `write_velocity`, and
//! `rename_burst` fields, but nothing populated them, so a process doing
//! mass renames with a plain name and low CPU was invisible. This module
//! populates them from real filesystem events.
//!
//! Honest limits, stated up front:
//! * inotify reports *paths*, not PIDs. Per-process attribution comes from
//!   /proc corroboration (per-PID `write_bytes` velocity, cwd under a
//!   watched tree, current-syscall sampling). When a burst is active but no
//!   process corroborates, the watcher reports a host-level anomaly with
//!   no PID — it never invents attribution.
//! * `write_velocity` here means file-write completions (CLOSE_WRITE) in
//!   the 10 s window, matching the scorer's `> 50` threshold in the same
//!   units. `entropy_delta` is normalized Shannon entropy (0..1) of the
//!   largest sample of written bytes in the window, matching the scorer's
//!   `> 0.7` threshold. `rename_burst` is true above 20 renames/window.
//! * fanotify (which would give true per-PID attribution) is unavailable
//!   in this environment — `fanotify_init` fails with EPERM even as root —
//!   so inotify + /proc corroboration is the userspace path that works
//!   here. The eBPF path remains the route to true per-process file-op
//!   telemetry.
//! * Watch paths come from `AHR_WATCH_PATHS` (colon-separated), defaulting
//!   to `$HOME`. The agent's own audit-log writes are never under a
//!   watched path in the test harness, and inotify has no PID to filter
//!   on, so keep `AHR_AUDIT_LOG` outside the watch paths.

use log::{info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Rolling window for burst accounting.
pub const WINDOW: Duration = Duration::from_secs(10);
/// Renames (MOVED_FROM) in one window that count as a burst.
pub const RENAME_BURST_THRESHOLD: u32 = 20;
/// Write completions (CLOSE_WRITE) in one window that count as velocity.
/// Same units as the scorer's `write_velocity > 50` threshold.
pub const WRITE_VELOCITY_THRESHOLD: u32 = 50;
/// Normalized Shannon entropy (0..1) above which written content looks
/// encrypted/compressed. Same threshold as the scorer's `entropy_delta`.
pub const ENTROPY_THRESHOLD: f32 = 0.7;
/// Per-process write throughput that corroborates attribution (bytes/sec).
pub const IO_VELOCITY_THRESHOLD_BPS: u64 = 100_000;
/// Bytes sampled from a written file for the entropy estimate.
const ENTROPY_SAMPLE_BYTES: usize = 4096;
/// Bounds for the recursive watch walk.
/// Re-scan the configured watch roots every N cycles: a root (or a
/// subdir) that did not exist at startup — a fresh build dir, a new
/// user folder, a recreated directory — would otherwise never be
/// watched. inotify_add_watch is idempotent for an already-watched
/// path, so the re-scan is cheap and safe.
const RESCAN_EVERY_CYCLES: u64 = 5;

/// A watch path that did not exist when the watcher started is not
/// an error — it is retried on the re-scan (see RESCAN_EVERY_CYCLES).
const MAX_WATCH_DIRS: usize = 4096;
const MAX_WATCH_DEPTH: usize = 8;

/// File signals as the detector bridge consumes them.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSignals {
    /// CLOSE_WRITE completions in the window.
    pub write_velocity: u32,
    /// True when renames in the window exceed the burst threshold.
    pub rename_burst: bool,
    /// Highest normalized entropy sampled from written files in the window.
    pub entropy_delta: f32,
    /// True when any burst condition holds.
    pub burst_active: bool,
    /// Raw rename count in the window (for anomaly records).
    pub renames: u32,
    /// Raw write-completion count in the window (for anomaly records).
    pub writes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EvKind {
    Write,
    Rename,
    Create,
    Delete,
}

pub struct FileWatcher {
    enabled: bool,
    fd: i32,
    watches: HashMap<i32, PathBuf>,
    watch_paths: Vec<PathBuf>,
    events: VecDeque<(Instant, EvKind)>,
    entropy_samples: VecDeque<(Instant, f32)>,
    io_baseline: HashMap<u32, (u64, Instant)>,
    io_velocity: HashMap<u32, u64>,
    overflowed: bool,
    cycles: u64,
}

impl FileWatcher {
    fn new() -> Self {
        let mut w = FileWatcher {
            enabled: false,
            fd: -1,
            watches: HashMap::new(),
            watch_paths: Vec::new(),
            events: VecDeque::new(),
            entropy_samples: VecDeque::new(),
            io_baseline: HashMap::new(),
            io_velocity: HashMap::new(),
            overflowed: false,
            cycles: 0,
        };
        w.setup();
        w
    }

    fn setup(&mut self) {
        let paths = watch_paths_from_env();
        if paths.is_empty() {
            warn!("file telemetry disabled: no watch paths (set AHR_WATCH_PATHS or $HOME)");
            return;
        }
        // SAFETY: inotify_init1 with non-blocking + close-on-exec; no
        // privileges required. A failure here disables file telemetry
        // only — the agent keeps running on name/pressure signals.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            warn!(
                "file telemetry disabled: inotify_init1 failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        self.fd = fd;
        self.watch_paths = paths.clone();
        for root in &paths {
            self.add_watch_recursive(root, 0);
        }
        if self.watches.is_empty() {
            warn!("file telemetry disabled: no directories could be watched");
            unsafe { libc::close(self.fd) };
            self.fd = -1;
            return;
        }
        self.enabled = true;
        self.take_io_baseline();
        info!(
            "file telemetry active: watching {} director{} under {:?} (inotify, 10 s window)",
            self.watches.len(),
            if self.watches.len() == 1 { "y" } else { "ies" },
            paths
        );
    }

    fn add_watch_recursive(&mut self, dir: &Path, depth: usize) {
        if depth > MAX_WATCH_DEPTH || self.watches.len() >= MAX_WATCH_DIRS {
            return;
        }
        // Skip symlinked directories (avoids loops) and unreadable ones.
        let md = match fs::symlink_metadata(dir) {
            Ok(m) => m,
            Err(_) => return,
        };
        if md.file_type().is_symlink() || !md.is_dir() {
            return;
        }
        let cpath = match CString::new(dir.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mask = (libc::IN_CLOSE_WRITE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_ONLYDIR
            | libc::IN_DONT_FOLLOW) as u32;
        let wd = unsafe { libc::inotify_add_watch(self.fd, cpath.as_ptr(), mask) };
        if wd < 0 {
            return;
        }
        self.watches.insert(wd, dir.to_path_buf());
        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                let is_dir = entry
                    .file_type()
                    .map(|t| t.is_dir())
                    .unwrap_or(false);
                if is_dir {
                    self.add_watch_recursive(&p, depth + 1);
                }
            }
        }
    }

    /// Drain pending inotify events, prune the window, refresh per-PID
    /// I/O velocities. Cheap no-op when file telemetry is disabled.
    /// Every RESCAN_EVERY_CYCLES cycles the configured roots are
    /// re-walked so directories created after startup get watched;
    /// while disabled, setup is retried on the same cadence so a
    /// watch path that appears later still enables telemetry.
    pub fn cycle(&mut self) {
        self.cycles += 1;
        if !self.enabled {
            if self.cycles % RESCAN_EVERY_CYCLES == 0 {
                self.setup();
            }
            return;
        }
        if self.cycles % RESCAN_EVERY_CYCLES == 0 {
            let roots = self.watch_paths.clone();
            for root in &roots {
                self.add_watch_recursive(root, 0);
            }
        }
        self.drain();
        self.prune();
        self.sample_io();
    }

    fn drain(&mut self) {
        let mut buf = [0u8; 65536];
        loop {
            // SAFETY: fd is a valid non-blocking inotify fd; buf is ours.
            let n = unsafe {
                libc::read(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break; // EAGAIN (empty) or an error — nothing more to read.
            }
            let n = n as usize;
            let mut off = 0usize;
            while off + 16 <= n {
                let wd = i32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
                let mask = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
                let len = u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
                let name_bytes = &buf[off + 16..(off + 16 + len).min(n)];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(len);
                let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
                off += 16 + len;
                self.handle_event(wd, mask, &name);
            }
        }
    }

    fn handle_event(&mut self, wd: i32, mask: u32, name: &str) {
        const ISDIR: u32 = libc::IN_ISDIR as u32;
        const Q_OVERFLOW: u32 = libc::IN_Q_OVERFLOW as u32;
        const IGNORED: u32 = libc::IN_IGNORED as u32;
        if mask & Q_OVERFLOW != 0 {
            warn!("file telemetry: inotify queue overflowed; window reset");
            self.overflowed = true;
            self.events.clear();
            self.entropy_samples.clear();
            return;
        }
        if mask & IGNORED != 0 {
            self.watches.remove(&wd);
            return;
        }
        let now = Instant::now();
        let dir = match self.watches.get(&wd) {
            Some(d) => d.clone(),
            None => return,
        };
        if mask & (libc::IN_CLOSE_WRITE as u32) != 0 && !name.is_empty() {
            self.events.push_back((now, EvKind::Write));
            let path = dir.join(name);
            if let Some(e) = sample_file_entropy(&path) {
                self.entropy_samples.push_back((now, e));
            }
        }
        if mask & (libc::IN_MOVED_FROM as u32) != 0 {
            self.events.push_back((now, EvKind::Rename));
        }
        if mask & (libc::IN_MOVED_TO as u32) != 0 && !name.is_empty() {
            // A file just moved into the watched tree: sample its entropy
            // here, not only on CLOSE_WRITE. A write-then-rename
            // workload renames the file before the drain reads the
            // CLOSE_WRITE path, so sampling only on close misses it.
            let path = dir.join(name);
            if let Some(e) = sample_file_entropy(&path) {
                self.entropy_samples.push_back((now, e));
            }
        }
        if mask & (libc::IN_CREATE as u32) != 0 {
            self.events.push_back((now, EvKind::Create));
            // A new subdirectory needs its own watch.
            if mask & ISDIR != 0 && !name.is_empty() {
                self.add_watch_recursive(&dir.join(name), 0);
            }
        }
        if mask & (libc::IN_DELETE as u32) != 0 {
            self.events.push_back((now, EvKind::Delete));
        }
    }

    fn prune(&mut self) {
        let now = Instant::now();
        while let Some((t, _)) = self.events.front() {
            if now.duration_since(*t) > WINDOW {
                self.events.pop_front();
            } else {
                break;
            }
        }
        while let Some((t, _)) = self.entropy_samples.front() {
            if now.duration_since(*t) > WINDOW {
                self.entropy_samples.pop_front();
            } else {
                break;
            }
        }
        if self.overflowed {
            self.overflowed = false;
        }
    }

    /// Current burst picture for the window.
    pub fn signals(&self) -> FileSignals {
        let mut writes = 0u32;
        let mut renames = 0u32;
        for (_, k) in &self.events {
            match k {
                EvKind::Write => writes += 1,
                EvKind::Rename => renames += 1,
                _ => {}
            }
        }
        let entropy = self
            .entropy_samples
            .iter()
            .map(|(_, e)| *e)
            .fold(0.0f32, f32::max);
        let rename_burst = renames > RENAME_BURST_THRESHOLD;
        let burst_active =
            rename_burst || writes > WRITE_VELOCITY_THRESHOLD || entropy > ENTROPY_THRESHOLD;
        FileSignals {
            write_velocity: writes,
            rename_burst,
            entropy_delta: entropy,
            burst_active,
            renames,
            writes,
        }
    }

    fn take_io_baseline(&mut self) {
        let now = Instant::now();
        for (pid, bytes) in read_all_io_wchar() {
            self.io_baseline.insert(pid, (bytes, now));
        }
    }

    /// Refresh per-PID write throughput (bytes/sec) against the baseline.
    /// Called once per detection cycle; the first call after init has a
    /// real interval behind it because startup sleeps ~400 ms first.
    /// A call made too soon after the previous one (dt < 100 ms) leaves
    /// both the baseline and the last velocity untouched — a rapid
    /// re-sample must never wipe a velocity that was just measured.
    fn sample_io(&mut self) {
        let now = Instant::now();
        let mut fresh: HashMap<u32, u64> = HashMap::new();
        let mut seen: HashSet<u32> = HashSet::new();
        for (pid, bytes) in read_all_io_wchar() {
            seen.insert(pid);
            match self.io_baseline.get(&pid) {
                Some((base, t0)) => {
                    let dt = now.duration_since(*t0).as_secs_f64();
                    if dt >= 0.1 {
                        let delta = bytes.saturating_sub(*base);
                        fresh.insert(pid, (delta as f64 / dt) as u64);
                        self.io_baseline.insert(pid, (bytes, now));
                    }
                    // dt too small: leave baseline and velocity alone.
                }
                None => {
                    self.io_baseline.insert(pid, (bytes, now));
                }
            }
        }
        // Drop velocities for exited processes only.
        self.io_velocity.retain(|pid, _| seen.contains(pid));
        for (pid, v) in fresh {
            self.io_velocity.insert(pid, v);
        }
    }

    /// Attribute an active burst to a process, if any corroboration
    /// exists. Returns None rather than guessing. Corroboration, in
    /// order: (1) highest per-PID write throughput above threshold;
    /// (2) a process whose cwd sits under a watched tree; (3) a process
    /// currently observed in a rename/write syscall.
    pub fn attribute(&self) -> Option<u32> {
        // (1) I/O velocity.
        let mut best: Option<(u32, u64)> = None;
        for (pid, v) in &self.io_velocity {
            if *v >= IO_VELOCITY_THRESHOLD_BPS {
                if best.map(|(_, bv)| *v > bv).unwrap_or(true) {
                    best = Some((*pid, *v));
                }
            }
        }
        if let Some((pid, _)) = best {
            return Some(pid);
        }
        // (2) cwd under a watched tree.
        for pid in list_pids() {
            if let Ok(cwd) = fs::read_link(format!("/proc/{}/cwd", pid)) {
                if self.watch_paths.iter().any(|w| cwd.starts_with(w)) {
                    return Some(pid);
                }
            }
        }
        // (3) syscall sampling — best effort; a fast renamer spends
        // most of its time in renameat2.
        for pid in list_pids() {
            if pid_in_syscall(pid, &[1, 82, 264, 316]) {
                return Some(pid);
            }
        }
        None
    }

    pub fn watch_paths(&self) -> Vec<String> {
        self.watch_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }
}

impl Drop for FileWatcher {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// Normalized Shannon entropy (0..1) of up to the first 4 KiB of a file.
/// Text is ~0.5; encrypted/compressed content is ~0.95+. Unreadable or
/// vanished files yield None (no sample, no signal).
fn sample_file_entropy(path: &Path) -> Option<f32> {
    use std::io::Read;
    // The agent's own read is not theft: note it so the canary watch
    // does not mistake this sampling open for a token hit.
    crate::honeytoken::note_self_access(path);
    let mut f = fs::File::open(path).ok()?;
    let mut buf = [0u8; ENTROPY_SAMPLE_BYTES];
    let mut n = 0usize;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    if n == 0 {
        return None;
    }
    Some(shannon_normalized(&buf[..n]))
}

fn shannon_normalized(data: &[u8]) -> f32 {
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

fn watch_paths_from_env() -> Vec<PathBuf> {
    if let Ok(v) = std::env::var("AHR_WATCH_PATHS") {
        let paths: Vec<PathBuf> = v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !paths.is_empty() {
            return paths;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return vec![PathBuf::from(home)];
        }
    }
    Vec::new()
}

/// Compiler/linker tools whose bulk file output is known to look like
/// encryption (compiled objects are high-entropy, written fast, renamed
/// into place). A process whose exe basename is one of these is never
/// turned into a *process flag by file activity alone* — the burst is
/// still recorded as a host-level anomaly. This is a false-positive
/// control, not a security boundary: it suppresses only the
/// file-activity leg, never a name/pressure detection, and a binary
/// renamed to look like a compiler would evade the file-activity flag
/// (documented tradeoff; the audit record notes the suppression).
const BUILDER_TOOLS: &[&str] = &[
    "rustc", "cargo", "gcc", "g++", "cc", "c++", "clang", "clang++", "ld", "ld.lld", "as",
    "go", "javac", "kotlinc", "swiftc", "tcc",
];

fn exe_name_is_builder(name: &str) -> bool {
    BUILDER_TOOLS.contains(&name)
}

/// True when the process's executable basename is a known
/// compiler/linker tool. Best effort — false on any read failure.
pub fn is_builder_tool(pid: u32) -> bool {
    match std::fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(p) => p
            .file_name()
            .map(|n| exe_name_is_builder(&n.to_string_lossy()))
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Whether file signals warrant turning an attributed burst into a
/// process flag. A process is flagged from file activity only on the
/// encryption pattern — high-entropy writes — and only when the
/// process is not a known builder tool. Bulk write/rename activity
/// without high entropy (backups, copies, builds of text) stays a
/// host-level anomaly, never a process action. Tradeoff, stated
/// plainly: a pure renamer (no content rewrite) and an encryptor
/// whose output entropy stays under the threshold are visible only as
/// anomalies; that is the price of not flagging every backup script.
pub fn warrants_process_flag(sig: FileSignals, allowlisted: bool) -> bool {
    sig.entropy_delta > ENTROPY_THRESHOLD && !allowlisted
}
///
/// `wchar` — bytes passed to write() by the process — is used instead
/// of `write_bytes` (bytes flushed to storage) deliberately: buffered
/// file writes sit in the page cache and reach `write_bytes` only on
/// asynchronous writeback, so `write_bytes` lags a fast writer by an
/// unbounded amount. `wchar` is immediate, which is what attribution
/// needs. It also counts pipe/socket/terminal writes, so it is
/// corroboration for an already-active burst, never a standalone
/// trigger.
fn read_all_io_wchar() -> Vec<(u32, u64)> {
    let mut out = Vec::new();
    for pid in list_pids() {
        let path = format!("/proc/{}/io", pid);
        if let Ok(text) = fs::read_to_string(&path) {
            for line in text.lines() {
                if let Some(v) = line.strip_prefix("wchar:") {
                    if let Ok(n) = v.trim().parse::<u64>() {
                        out.push((pid, n));
                    }
                    break;
                }
            }
        }
    }
    out
}

fn list_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for entry in rd.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    pids
}

/// True when the process's current syscall is one of the given numbers
/// (x86_64: 1 write, 82 rename, 264 renameat, 316 renameat2).
/// Best effort — returns false on any read/parse failure.
fn pid_in_syscall(pid: u32, numbers: &[u64]) -> bool {
    let text = match fs::read_to_string(format!("/proc/{}/syscall", pid)) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let first = text.split_whitespace().next().unwrap_or("");
    match first.parse::<u64>() {
        Ok(n) => numbers.contains(&n),
        Err(_) => false,
    }
}

// ---- global singleton -------------------------------------------------

static WATCHER: OnceLock<Mutex<FileWatcher>> = OnceLock::new();

fn global() -> &'static Mutex<FileWatcher> {
    WATCHER.get_or_init(|| Mutex::new(FileWatcher::new()))
}

/// Initialize file telemetry (idempotent). Call once at startup, before
/// the ~400 ms detection warm-up, so the first cycle's I/O delta covers
/// a real interval.
pub fn init() {
    let _ = global();
}

/// One telemetry cycle: drain events, prune the window, refresh I/O.
/// No-op when file telemetry is disabled.
pub fn cycle() {
    if let Ok(mut w) = global().lock() {
        w.cycle();
    }
}

/// Current burst picture (zeroed when disabled).
pub fn signals() -> FileSignals {
    global()
        .lock()
        .map(|w| w.signals())
        .unwrap_or_default()
}

/// True when any burst condition currently holds.
pub fn burst_active() -> bool {
    signals().burst_active
}

/// Attribute the active burst to a process, if corroboration exists.
pub fn attribute() -> Option<u32> {
    global().lock().ok()?.attribute()
}

/// Watch paths as configured (for anomaly records).
pub fn watch_paths() -> Vec<String> {
    global()
        .lock()
        .map(|w| w.watch_paths())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_bytes_is_zero() {
        assert!(shannon_normalized(&[b'x'; 4096]) < 0.01);
    }

    #[test]
    fn entropy_of_random_bytes_is_near_one() {
        // Deterministic pseudo-random bytes (xorshift) — no RNG dep.
        let mut x: u32 = 0x12345678;
        let mut buf = [0u8; 4096];
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x & 0xff) as u8;
        }
        assert!(shannon_normalized(&buf) > 0.9);
    }

    #[test]
    fn entropy_of_text_is_midrange() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(90);
        let e = shannon_normalized(&text);
        assert!(e > 0.3 && e < 0.7, "text entropy was {e}");
    }

    #[test]
    fn burst_thresholds_behave() {
        let mut w = FileWatcher {
            enabled: true,
            fd: -1,
            watches: HashMap::new(),
            watch_paths: Vec::new(),
            events: VecDeque::new(),
            entropy_samples: VecDeque::new(),
            io_baseline: HashMap::new(),
            io_velocity: HashMap::new(),
            overflowed: false,
            cycles: 0,
        };
        let now = Instant::now();
        for _ in 0..(RENAME_BURST_THRESHOLD + 1) {
            w.events.push_back((now, EvKind::Rename));
        }
        let s = w.signals();
        assert!(s.rename_burst);
        assert!(s.burst_active);
        assert_eq!(s.renames, RENAME_BURST_THRESHOLD + 1);
    }

    #[test]
    fn old_events_age_out_of_window() {
        let mut w = FileWatcher {
            enabled: true,
            fd: -1,
            watches: HashMap::new(),
            watch_paths: Vec::new(),
            events: VecDeque::new(),
            entropy_samples: VecDeque::new(),
            io_baseline: HashMap::new(),
            io_velocity: HashMap::new(),
            overflowed: false,
            cycles: 0,
        };
        let old = Instant::now() - WINDOW - Duration::from_secs(1);
        w.events.push_back((old, EvKind::Rename));
        w.events.push_back((Instant::now(), EvKind::Rename));
        w.prune();
        assert_eq!(w.signals().renames, 1);
    }

    #[test]
    fn rapid_resample_keeps_last_velocity() {
        // Regression test: a second sample_io() immediately after the
        // first must not wipe the velocity map (the first version
        // retained only pids present in the fresh set, which was empty
        // on a sub-100 ms re-sample — exactly the --once call pattern,
        // where detect_file_activity() re-samples right after
        // detect_ransomware_behavior()).
        let mut w = FileWatcher {
            enabled: true,
            fd: -1,
            watches: HashMap::new(),
            watch_paths: Vec::new(),
            events: VecDeque::new(),
            entropy_samples: VecDeque::new(),
            io_baseline: HashMap::new(),
            io_velocity: HashMap::new(),
            overflowed: false,
            cycles: 0,
        };
        // Seed a baseline for pid 1 from one second ago.
        let base = read_all_io_wchar()
            .into_iter()
            .find(|(pid, _)| *pid == 1)
            .map(|(_, bytes)| bytes)
            .unwrap_or(0);
        w.io_baseline
            .insert(1, (base, Instant::now() - Duration::from_secs(1)));
        w.sample_io();
        let first = w.io_velocity.get(&1).copied();
        assert!(first.is_some(), "first sample should record pid 1");
        w.sample_io();
        assert_eq!(
            w.io_velocity.get(&1).copied(),
            first,
            "immediate re-sample must not wipe the velocity"
        );
    }

    #[test]
    fn process_flag_requires_entropy_and_no_allowlist() {
        // S7 shape: high entropy + renames + velocity -> flags.
        let s7 = FileSignals {
            write_velocity: 80,
            rename_burst: true,
            entropy_delta: 0.99,
            burst_active: true,
            renames: 100,
            writes: 80,
        };
        assert!(warrants_process_flag(s7, false));
        // B4 shape: renames + velocity, low entropy -> anomaly only.
        let b4 = FileSignals {
            entropy_delta: 0.58,
            ..s7
        };
        assert!(!warrants_process_flag(b4, false));
        // B1 shape: high entropy but a builder tool -> anomaly only.
        assert!(!warrants_process_flag(s7, true));
        // Velocity alone, no entropy -> anomaly only.
        let vel_only = FileSignals {
            entropy_delta: 0.2,
            rename_burst: false,
            ..s7
        };
        assert!(!warrants_process_flag(vel_only, false));
    }

    #[test]
    fn builder_tool_names_match() {
        assert!(exe_name_is_builder("rustc"));
        assert!(exe_name_is_builder("cargo"));
        assert!(exe_name_is_builder("gcc"));
        assert!(exe_name_is_builder("ld"));
        assert!(!exe_name_is_builder("python3"));
        assert!(!exe_name_is_builder("encryptor"));
        assert!(!exe_name_is_builder("rustc-malware"));
    }

    #[test]
    fn rescan_re_adding_a_watched_dir_is_idempotent() {
        // The periodic re-scan calls add_watch_recursive on roots that
        // are already watched; it must not duplicate watch entries.
        let dir = std::env::temp_dir().join("ahr-rescan-test");
        let _ = fs::create_dir_all(&dir);
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        let mut w = FileWatcher {
            enabled: true,
            fd,
            watches: HashMap::new(),
            watch_paths: vec![dir.clone()],
            events: VecDeque::new(),
            entropy_samples: VecDeque::new(),
            io_baseline: HashMap::new(),
            io_velocity: HashMap::new(),
            overflowed: false,
            cycles: 0,
        };
        w.add_watch_recursive(&dir, 0);
        assert_eq!(w.watches.len(), 1);
        w.add_watch_recursive(&dir, 0);
        assert_eq!(w.watches.len(), 1, "re-scan must not duplicate watches");
        // Do NOT close fd here: `w` owns it and its Drop closes it.
        // Closing it manually double-closes the number once the kernel
        // recycles it to another thread's live fd — that aborted the
        // test binary twice (2026-11-26, IO-safety violation) and left
        // the integration test's synthetic spinner orphaned, which then
        // tripped the next runs' baselines.
        let _ = fs::remove_dir_all(&dir);
    }
}
