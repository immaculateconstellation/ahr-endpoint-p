//! Honeytokens (canaries) — the dye pack.
//!
//! Every file that leaves the machine carries a unique token, and every
//! planted dummy file carries one too. The token is a marker line
//! appended to the file (`AHR-CANARY:<id>`) plus a registry entry that
//! says which file, which token, where it was headed, and whether the
//! file is a decoy. When a token-bearing file is opened or read by any
//! process other than AHR itself, the canary watch logs a hit to the
//! audit trail: token, file, reader PID/exe when attribution succeeds,
//! and whether the file was a decoy.
//!
//! The dye-pack property, stated plainly: the *protection* is public
//! (AHR marks files) while the *placement* is secret (which files carry
//! tokens, which files are decoys). A thief cannot tell a marked file
//! from an unmarked one, so taking anything risks exposure — and the
//! token firing is the dye going off: proof the file was taken and
//! used, which is the evidence trail.
//!
//! Honest limits:
//! * A token only reports when the file is USED (opened/read). Passive
//!   copying that never opens the file through this host's filesystem
//!   does not trip it — a token is a tripwire, not a tracker.
//! * Attribution comes from /proc fd corroboration at drain time. A
//!   quick open/read/close may already be gone when the watcher drains,
//!   so the hit is logged with `reader_pid: None` — the inotify event
//!   itself is the evidence; attribution is a bonus, never invented.
//! * The canary watch is inotify (IN_OPEN/IN_ACCESS) on the configured
//!   canary dirs. It is a userspace watch, not a kernel gate: it sees
//!   use, it does not block it. Blocking needs fanotify/LSM on a real
//!   host (both unavailable in this container).
//! * Self-access suppression has a narrow blind spot: a foreign open
//!   within the quiet window (5 s) after AHR itself read the same file
//!   is suppressed along with the agent's own open — but only when no
//!   foreign reader still holds the file. Attribution runs first: a
//!   foreign holder is always a hit, never suppressed by the note.
//! * The watcher never reads a file inside a watched dir without
//!   noting self-access first, and the registry file itself can never
//!   fire (its events are watcher noise). Otherwise the watcher's own
//!   reads would feed its own drain forever: every lookup reads the
//!   registry, and every read raises IN_OPEN/IN_ACCESS on the watch.
//!   (2026-11-18: the first watcher tests spun exactly this way — the
//!   registry lived inside the watched dir and the drain never
//!   emptied. The fix is the ordering in `handle_event`: registry
//!   events ignored, attribution before the self-access check, and a
//!   bounded tail-scan for the fallback.)
//! * The drain is capped per cycle (see MAX_EVENTS_PER_CYCLE) so a
//!   pathological directory cannot stall the agent loop.
//!
//! Registry paths are explicit parameters (`*_at` functions) with
//! env-based wrappers for production; tests pass temp paths so parallel
//! tests never share registry state.

use crate::audit;
use log::{info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Marker line appended to a token-bearing file.
pub const MARKER_PREFIX: &str = "AHR-CANARY:";
/// How long after AHR itself opens a canary file the watcher ignores
/// access events for that path (prevents self-inflicted hits: the
/// agent's own scan/embed opens would otherwise look like theft).
/// Applies only when no foreign reader still holds the file — see
/// `handle_event`.
const SELF_ACCESS_QUIET: Duration = Duration::from_secs(5);
/// Bytes read from a file's tail when scanning for a marker (the
/// marker is a trailer, so the tail is where it lives).
const TAIL_SCAN_BYTES: u64 = 4096;
/// Backstop on the drain: a cycle that hits this many events stops
/// draining and warns, so a pathological directory cannot stall the
/// agent loop. (The ordering in `handle_event` is what keeps the
/// drain finite; the cap is only a guard.)
const MAX_EVENTS_PER_CYCLE: usize = 10_000;
/// Bounds for the recursive canary watch walk.
const MAX_WATCH_DIRS: usize = 256;
const MAX_WATCH_DEPTH: usize = 6;

/// One registry entry: which file, which token, where it was headed,
/// and whether the file is a decoy (dye pack) rather than a real asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenEntry {
    pub token_id: String,
    pub file: String,
    pub sha256: String,
    pub destination: Option<String>,
    pub is_decoy: bool,
    pub kind: String,
    pub created_ts_unix: u64,
}

/// One observed token use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHit {
    pub token_id: String,
    pub file: PathBuf,
    pub reader_pid: Option<u32>,
    pub reader_exe: Option<String>,
    pub is_decoy: bool,
}

/// A fresh token id: 24 hex chars from the OS-seeded RNG.
pub fn new_token_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.gen();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// The marker line for a token id.
pub fn marker_for(token_id: &str) -> String {
    format!("{}{}", MARKER_PREFIX, token_id)
}

/// Scan bytes for a canary marker. Returns the token id, if any.
pub fn find_token_in_bytes(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        if let Some(id) = line.strip_prefix(MARKER_PREFIX) {
            let id = id.trim();
            if !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// SHA-256 hex of bytes (registry integrity field).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Registry path: `AHR_CANARY_REGISTRY`, else `$HOME/.ahr/canary_registry.json`.
pub fn registry_path() -> PathBuf {
    if let Ok(v) = std::env::var("AHR_CANARY_REGISTRY") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".ahr").join("canary_registry.json")
}

/// Load the registry at `path` (empty when missing or unreadable — a
/// missing registry means "no tokens yet", never an error that stops
/// the agent).
pub fn load_registry_at(path: &Path) -> Vec<TokenEntry> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn save_registry_at(path: &Path, entries: &[TokenEntry]) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(entries) {
        Ok(text) => {
            if let Err(e) = fs::write(path, text) {
                warn!("canary registry write failed ({}): {}", path.display(), e);
            }
        }
        Err(e) => warn!("canary registry serialization failed: {}", e),
    }
}

/// Register (or replace, by token id) one entry at `path`.
pub fn register_at(path: &Path, entry: TokenEntry) {
    let mut entries = load_registry_at(path);
    entries.retain(|e| e.token_id != entry.token_id);
    entries.push(entry);
    save_registry_at(path, &entries);
}

/// Registry entry for a file path at `path`, if the file carries a token.
pub fn lookup_by_path_at(registry: &Path, file: &Path) -> Option<TokenEntry> {
    let needle = file.to_string_lossy().into_owned();
    load_registry_at(registry)
        .into_iter()
        .find(|e| e.file == needle)
}

/// Registry entry for a token id at `path`.
pub fn lookup_by_id_at(registry: &Path, token_id: &str) -> Option<TokenEntry> {
    load_registry_at(registry)
        .into_iter()
        .find(|e| e.token_id == token_id)
}

/// Set the destination on an existing registry entry (the probe seals
/// a file for a destination after the token was minted). No-op when
/// the token is not registered.
pub fn set_destination_at(registry: &Path, token_id: &str, destination: &str) {
    let mut entries = load_registry_at(registry);
    let mut changed = false;
    for e in entries.iter_mut() {
        if e.token_id == token_id {
            e.destination = Some(destination.to_string());
            changed = true;
        }
    }
    if changed {
        save_registry_at(registry, &entries);
    }
}

/// The token a file already carries, if any (registry first, then a
/// byte scan of the file itself — the registry is the fast path, the
/// scan is the truth when a file was moved).
pub fn file_token_at(registry: &Path, path: &Path) -> Option<String> {
    if let Some(entry) = lookup_by_path_at(registry, path) {
        return Some(entry.token_id);
    }
    let data = fs::read(path).ok()?;
    find_token_in_bytes(&data)
}

/// Embed a token in a file (append a marker trailer) and register it
/// in `registry`. Idempotent: a file that already carries a token
/// keeps it and the existing id is returned — no file is ever
/// double-marked. Returns the token id. The trailer append does not
/// disturb readers: text files gain one line, archives and executables
/// gain trailing bytes their parsers ignore.
pub fn embed_token_at(
    path: &Path,
    registry: &Path,
    destination: Option<String>,
    is_decoy: bool,
    kind: &str,
) -> Result<String, String> {
    if let Some(existing) = file_token_at(registry, path) {
        return Ok(existing);
    }
    let token_id = new_token_id();
    let marker = format!("\n{}\n", marker_for(&token_id));
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open {} for token embed: {}", path.display(), e))?;
        f.write_all(marker.as_bytes())
            .map_err(|e| format!("cannot append token to {}: {}", path.display(), e))?;
    }
    note_self_access(path);
    let data = fs::read(path).map_err(|e| format!("cannot re-read {}: {}", path.display(), e))?;
    register_at(
        registry,
        TokenEntry {
            token_id: token_id.clone(),
            file: path.to_string_lossy().into_owned(),
            sha256: sha256_hex(&data),
            destination,
            is_decoy,
            kind: kind.to_string(),
            created_ts_unix: now_unix(),
        },
    );
    info!(
        "canary embedded: {} token={} decoy={}",
        path.display(),
        token_id,
        is_decoy
    );
    Ok(token_id)
}

/// Embed a token in a file, registering at the configured registry.
pub fn embed_token(
    path: &Path,
    destination: Option<String>,
    is_decoy: bool,
    kind: &str,
) -> Result<String, String> {
    embed_token_at(path, &registry_path(), destination, is_decoy, kind)
}

/// Record that AHR itself just opened this path, so the canary watch
/// does not mistake the agent's own access for theft.
pub fn note_self_access(path: &Path) {
    if let Ok(mut w) = self_access().lock() {
        w.insert(path.to_path_buf(), Instant::now());
    }
}

fn self_access() -> &'static Mutex<HashMap<PathBuf, Instant>> {
    static SELF: OnceLock<Mutex<HashMap<PathBuf, Instant>>> = OnceLock::new();
    SELF.get_or_init(|| Mutex::new(HashMap::new()))
}

fn was_self_access(path: &Path) -> bool {
    if let Ok(mut w) = self_access().lock() {
        w.retain(|_, t| t.elapsed() < SELF_ACCESS_QUIET);
        return w.contains_key(path);
    }
    false
}

/// Find a process (other than this one) holding `path` open, via
/// /proc/*/fd. Best effort — None when no foreign holder is visible
/// right now (a fast reader may already be gone).
pub fn find_reader(path: &Path) -> Option<(u32, String)> {
    let mine = std::process::id();
    let target = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => path.to_path_buf(),
    };
    let rd = fs::read_dir("/proc").ok()?;
    for entry in rd.flatten() {
        let pid: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == mine {
            continue;
        }
        let fd_dir = format!("/proc/{}/fd", pid);
        let fds = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                if link == target {
                    let exe = fs::read_link(format!("/proc/{}/exe", pid))
                        .ok()
                        .and_then(|p| {
                            p.file_name().map(|n| n.to_string_lossy().into_owned())
                        })
                        .unwrap_or_default();
                    return Some((pid, exe));
                }
            }
        }
    }
    None
}

// ---- canary watch (inotify) -------------------------------------------

pub struct CanaryWatcher {
    enabled: bool,
    fd: i32,
    watches: HashMap<i32, PathBuf>,
    watch_dirs: Vec<PathBuf>,
    registry: PathBuf,
    logged: HashSet<(String, Option<u32>)>,
}

impl CanaryWatcher {
    fn new_with_registry(dirs: Vec<PathBuf>, registry: PathBuf) -> Self {
        let mut w = CanaryWatcher {
            enabled: false,
            fd: -1,
            watches: HashMap::new(),
            watch_dirs: dirs,
            registry,
            logged: HashSet::new(),
        };
        w.setup();
        w
    }

    fn new(dirs: Vec<PathBuf>) -> Self {
        Self::new_with_registry(dirs, registry_path())
    }

    fn setup(&mut self) {
        if self.watch_dirs.is_empty() {
            return;
        }
        // SAFETY: inotify_init1 non-blocking + close-on-exec; no
        // privileges required. Failure disables the canary watch only.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            warn!(
                "canary watch disabled: inotify_init1 failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        self.fd = fd;
        for root in self.watch_dirs.clone() {
            self.add_watch_recursive(&root, 0);
        }
        if self.watches.is_empty() {
            warn!("canary watch disabled: no directories could be watched");
            unsafe { libc::close(self.fd) };
            self.fd = -1;
            return;
        }
        self.enabled = true;
        info!(
            "canary watch active: {} director{} under {:?} (IN_OPEN/IN_ACCESS)",
            self.watches.len(),
            if self.watches.len() == 1 { "y" } else { "ies" },
            self.watch_dirs
        );
    }

    fn add_watch_recursive(&mut self, dir: &Path, depth: usize) {
        if depth > MAX_WATCH_DEPTH || self.watches.len() >= MAX_WATCH_DIRS {
            return;
        }
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
        let mask = (libc::IN_OPEN
            | libc::IN_ACCESS
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_TO
            | libc::IN_MOVED_FROM
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
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    self.add_watch_recursive(&p, depth + 1);
                }
            }
        }
    }

    /// Drain pending access events and return the token hits found.
    /// Each hit is also written to the audit trail. A hit is logged
    /// once per (token, reader) for the watcher's lifetime — repeat
    /// opens by the same reader are the same incident, not new ones.
    pub fn cycle(&mut self) -> Vec<TokenHit> {
        let mut hits = Vec::new();
        if !self.enabled {
            return hits;
        }
        let mut buf = [0u8; 65536];
        let mut drained = 0usize;
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
                break;
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
                drained += 1;
                if drained >= MAX_EVENTS_PER_CYCLE {
                    warn!(
                        "canary watch: drain cap reached ({} events); stopping this cycle",
                        MAX_EVENTS_PER_CYCLE
                    );
                    return hits;
                }
                if let Some(hit) = self.handle_event(wd, mask, &name) {
                    hits.push(hit);
                }
            }
        }
        hits
    }

    /// Scan the tail of a file for a canary marker (bounded read: the
    /// marker is a trailer). Used only when the file is not in the
    /// registry — e.g. it was moved after being sealed. The read is
    /// noted as self-access first: reading a watched file raises
    /// IN_OPEN/IN_ACCESS on this very watch, and an unnoted read
    /// would feed the drain forever.
    fn find_token_in_tail(&self, path: &Path) -> Option<String> {
        use std::io::{Read, Seek, SeekFrom};
        note_self_access(path);
        let mut f = fs::File::open(path).ok()?;
        let len = f.metadata().ok()?.len();
        let start = len.saturating_sub(TAIL_SCAN_BYTES);
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).ok()?;
        find_token_in_bytes(&buf)
    }

    fn handle_event(&mut self, wd: i32, mask: u32, name: &str) -> Option<TokenHit> {
        const ISDIR: u32 = libc::IN_ISDIR as u32;
        const IGNORED: u32 = libc::IN_IGNORED as u32;
        if mask & IGNORED != 0 {
            self.watches.remove(&wd);
            return None;
        }
        let dir = self.watches.get(&wd)?.clone();
        if mask & (libc::IN_CREATE as u32) != 0 && mask & ISDIR != 0 && !name.is_empty() {
            self.add_watch_recursive(&dir.join(name), 0);
            return None;
        }
        let is_access = mask & ((libc::IN_OPEN as u32) | (libc::IN_ACCESS as u32)) != 0;
        if !is_access || name.is_empty() {
            return None;
        }
        let path = dir.join(name);
        // The registry file itself can never fire: every lookup reads
        // it, so its own access events are watcher noise, not use.
        if path == self.registry {
            return None;
        }
        // Only token-bearing files can fire. Registry first; a
        // bounded tail-scan second, for files moved after sealing.
        let entry = match lookup_by_path_at(&self.registry, &path) {
            Some(e) => e,
            None => match self.find_token_in_tail(&path) {
                Some(id) => match lookup_by_id_at(&self.registry, &id) {
                    Some(e) => e,
                    None => return None,
                },
                None => return None,
            },
        };
        // Attribution FIRST: a foreign reader still holding the file
        // is a hit no matter what — the agent's own recent read of
        // the same path never suppresses it.
        let (reader_pid, reader_exe) = match find_reader(&path) {
            Some((pid, exe)) => (Some(pid), Some(exe)),
            None => (None, None),
        };
        if reader_pid.is_none() && was_self_access(&path) {
            // Nobody holds the file and AHR itself read it recently:
            // the agent's own sampling/embed open, not theft.
            return None;
        }
        // Nobody holds it and AHR did not read it: a fast foreign
        // reader came and went. The event itself is the evidence.
        let key = (entry.token_id.clone(), reader_pid);
        if !self.logged.insert(key) {
            return None; // Same (token, reader) already reported.
        }
        let hit = TokenHit {
            token_id: entry.token_id.clone(),
            file: path.clone(),
            reader_pid,
            reader_exe: reader_exe.clone(),
            is_decoy: entry.is_decoy,
        };
        let record = audit::build_token_hit(
            &entry.token_id,
            &path.to_string_lossy(),
            reader_pid,
            reader_exe,
            entry.is_decoy,
            entry.destination.clone(),
            true, // dry_run: the watch reports; enforcement is a policy call above it
        );
        audit::emit_token_hit(&record);
        if entry.is_decoy {
            warn!(
                "CANARY HIT (decoy): token={} file={} reader={:?} — dye pack tripped",
                entry.token_id,
                path.display(),
                reader_pid
            );
        } else {
            warn!(
                "CANARY HIT: token={} file={} reader={:?}",
                entry.token_id,
                path.display(),
                reader_pid
            );
        }
        Some(hit)
    }
}

impl Drop for CanaryWatcher {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

// ---- global singleton -------------------------------------------------

static WATCHER: OnceLock<Mutex<CanaryWatcher>> = OnceLock::new();

/// Canary dirs: `AHR_CANARY_DIRS` (colon-separated), else the
/// quarantine dir when one is configured.
pub fn canary_dirs_from_env() -> Vec<PathBuf> {
    if let Ok(v) = std::env::var("AHR_CANARY_DIRS") {
        let paths: Vec<PathBuf> = v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !paths.is_empty() {
            return paths;
        }
    }
    if let Ok(v) = std::env::var("AHR_QUARANTINE_DIR") {
        if !v.is_empty() {
            return vec![PathBuf::from(v)];
        }
    }
    Vec::new()
}

/// Initialize the canary watch (idempotent). Call once at startup when
/// canary dirs are configured; a no-op otherwise.
pub fn init_canary_watch() {
    let dirs = canary_dirs_from_env();
    if dirs.is_empty() {
        return;
    }
    let _ = WATCHER.get_or_init(|| Mutex::new(CanaryWatcher::new(dirs)));
}

/// One canary cycle: drain access events, return the hits found.
/// No-op (empty) when the watch is disabled.
pub fn cycle() -> Vec<TokenHit> {
    match WATCHER.get() {
        Some(m) => m.lock().map(|mut w| w.cycle()).unwrap_or_default(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn test_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(name);
        let _ = fs::create_dir_all(&d);
        d
    }

    #[test]
    fn token_ids_are_unique_hex() {
        let a = new_token_id();
        let b = new_token_id();
        assert_eq!(a.len(), 24);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn marker_round_trips() {
        let id = new_token_id();
        let data = format!("hello\n{}\nworld\n", marker_for(&id));
        assert_eq!(find_token_in_bytes(data.as_bytes()), Some(id));
        assert_eq!(find_token_in_bytes(b"nothing here"), None);
    }

    #[test]
    fn embed_is_idempotent_and_verifiable() {
        let dir = test_dir("ahr-canary-test-embed");
        let reg = dir.join("registry.json");
        let p = dir.join("embed.txt");
        fs::write(&p, b"secret data\n").unwrap();
        let id1 = embed_token_at(&p, &reg, Some("dest-a".to_string()), false, "test").unwrap();
        let id2 = embed_token_at(&p, &reg, Some("dest-a".to_string()), false, "test").unwrap();
        assert_eq!(id1, id2, "re-embed must return the same token");
        let data = fs::read(&p).unwrap();
        assert_eq!(find_token_in_bytes(&data), Some(id1.clone()));
        assert_eq!(file_token_at(&reg, &p), Some(id1.clone()));
        let entry = lookup_by_path_at(&reg, &p).expect("registry entry");
        assert_eq!(entry.token_id, id1);
        assert!(!entry.is_decoy);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_reader_excludes_self() {
        // A file open only by this test process has no *foreign* reader.
        let dir = test_dir("ahr-canary-test-self");
        let p = dir.join("self.txt");
        fs::write(&p, b"data\n").unwrap();
        let _f = fs::File::open(&p).unwrap();
        assert_eq!(find_reader(&p), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_reader_finds_foreign_holder() {
        // A child `sleep` holding the file as stdin is a foreign reader.
        let dir = test_dir("ahr-canary-test-foreign");
        let p = dir.join("foreign.txt");
        fs::write(&p, b"data\n").unwrap();
        let f = fs::File::open(&p).unwrap();
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::from(f))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        std::thread::sleep(Duration::from_millis(200));
        let found = find_reader(&p);
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
        let (pid, exe) = found.expect("sleep should be found holding the file");
        assert_eq!(pid, child.id());
        assert_eq!(exe, "sleep");
    }

    #[test]
    fn watcher_reports_foreign_open() {
        // End-to-end for the watch: a canary file in a watched dir,
        // opened (and held) by a foreign process, produces a hit.
        let dir = test_dir("ahr-canary-test-watch");
        let reg = dir.join("registry.json");
        let p = dir.join("watched.txt");
        fs::write(&p, b"watched data\n").unwrap();
        let id = embed_token_at(&p, &reg, None, false, "test").unwrap();
        let mut w = CanaryWatcher::new_with_registry(vec![dir.clone()], reg);
        assert!(w.enabled);
        // Foreign reader: hold the file open, then drain.
        let f = fs::File::open(&p).unwrap();
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::from(f))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        std::thread::sleep(Duration::from_millis(200));
        let hits = w.cycle();
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(hits.len(), 1, "one hit expected, got {:?}", hits);
        assert_eq!(hits[0].token_id, id);
        assert_eq!(hits[0].reader_pid, Some(child.id()));
        assert!(!hits[0].is_decoy);
    }

    #[test]
    fn watcher_ignores_self_access() {
        // The agent's own embed opens the file; the watch must not
        // report that as theft.
        let dir = test_dir("ahr-canary-test-selfwatch");
        let reg = dir.join("registry.json");
        let p = dir.join("self.txt");
        fs::write(&p, b"self data\n").unwrap();
        let mut w = CanaryWatcher::new_with_registry(vec![dir.clone()], reg.clone());
        assert!(w.enabled);
        let _id = embed_token_at(&p, &reg, None, false, "test").unwrap();
        // Drain immediately: the embed's own open must be suppressed.
        let hits = w.cycle();
        let _ = fs::remove_dir_all(&dir);
        assert!(hits.is_empty(), "self access must not fire: {:?}", hits);
    }
}
