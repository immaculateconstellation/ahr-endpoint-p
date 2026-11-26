//! Dummy (decoy) files — the dye pack, planted.
//!
//! A decoy is a believable fake: same kind of values, same shape,
//! plausible name, plausible content — planted where a file-grab would
//! take it. Whoever takes it takes the honeytoken with it, and the
//! token firing is the dye going off: proof the file was taken and
//! used, and the log behind it is the evidence trail for prosecution.
//!
//! Two rules, enforced by construction:
//! * A decoy is believable to whoever grabs it, but registered as a
//!   decoy (`is_decoy: true`) in the canary registry, so AHR and the
//!   owner never mistake it for a real asset. The registry is the only
//!   place that knows.
//! * Decoy values are fake by construction: random passwords, fake
//!   keys in canary formats, invented ledger rows. Nothing in a decoy
//!   is a real credential, a real account, or a real person's data.

use crate::honeytoken;
use rand::Rng;
use std::fs;
use std::path::{Path, PathBuf};

/// Decoy kinds. Unknown kinds are an error at the CLI, never a
/// silently different file.
pub const KINDS: &[&str] = &["credentials", "financial", "keys", "document"];

fn rand_hex(rng: &mut impl Rng, n: usize) -> String {
    (0..n)
        .map(|_| format!("{:x}", rng.gen_range(0..16)))
        .collect()
}

fn fake_password(rng: &mut impl Rng) -> String {
    const WORDS: &[&str] = &[
        "river", "harbor", "meadow", "copper", "willow", "summer", "falcon", "marble",
    ];
    format!(
        "{}{}{}{}",
        WORDS[rng.gen_range(0..WORDS.len())],
        WORDS[rng.gen_range(0..WORDS.len())],
        rng.gen_range(10..99),
        if rng.gen_bool(0.5) { "!" } else { "#" }
    )
}

fn credentials_content(rng: &mut impl Rng) -> String {
    let mut s = String::from("# passwords — DO NOT SHARE\n# (rotated quarterly; see vault)\n\n");
    let services = [
        ("email", "ops@example.net"),
        ("backup-console", "admin@example.net"),
        ("vendor-portal", "billing@example.net"),
        ("cloud-storage", "backup@example.net"),
    ];
    for (svc, user) in services {
        s.push_str(&format!("{}: {} / {}\n", svc, user, fake_password(rng)));
    }
    // A fake key in canary format — random, not a real credential.
    s.push_str(&format!(
        "\nAWS_ACCESS_KEY_ID=AKIA{}\nAWS_SECRET_ACCESS_KEY={}\n",
        rand_hex(rng, 16).to_uppercase(),
        rand_hex(rng, 40)
    ));
    s
}

fn financial_content(rng: &mut impl Rng) -> String {
    let mut s = String::from("date,vendor,description,amount_usd\n");
    let vendors = [
        ("Office Supply Co", "paper and toner"),
        ("Cloud Hosting LLC", "monthly hosting"),
        ("Fuel & Fleet", "diesel"),
        ("Parts Warehouse", "filters and belts"),
        ("Phone Carrier", "monthly service"),
    ];
    for i in 0..12 {
        let (vendor, desc) = vendors[rng.gen_range(0..vendors.len())];
        let amount = rng.gen_range(45..2400) as f64 + rng.gen_range(0..100) as f64 / 100.0;
        s.push_str(&format!(
            "2026-{:02}-{:02},{},{},{:.2}\n",
            rng.gen_range(1..12),
            rng.gen_range(1..28),
            vendor,
            desc,
            amount
        ));
        let _ = i;
    }
    s
}

fn keys_content(rng: &mut impl Rng) -> String {
    // A fake private-key block: correct shape, random base64 body —
    // a tripwire, not a key. No real key material is ever generated.
    let mut body = String::new();
    for _ in 0..8 {
        body.push_str(&rand_hex(rng, 48));
        body.push('\n');
    }
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n# backup key — store offline\n",
        body
    )
}

fn document_content(rng: &mut impl Rng) -> String {
    let topics = [
        "Q4 planning",
        "vendor review",
        "inventory count",
        "route schedule",
        "budget check",
    ];
    let topic = topics[rng.gen_range(0..topics.len())];
    format!(
        "# {}\n\n- Follow up with the vendor on the outstanding invoice.\n- Confirm the delivery window for next week.\n- Review the numbers before the end of the month.\n- File the receipts from the last trip.\n\nNext review: 2026-12-{:02}.\n",
        topic,
        rng.gen_range(1..28)
    )
}

/// File name for a decoy kind (plausible, ordinary, forgettable — a
/// dye pack must look like the rest of the money).
fn filename_for(kind: &str, rng: &mut impl Rng) -> String {
    match kind {
        "credentials" => "passwords.txt".to_string(),
        "financial" => format!("Q{}-ledger.csv", rng.gen_range(1..5)),
        "keys" => "backup-keys.txt".to_string(),
        "document" => "meeting-notes.md".to_string(),
        _ => format!("notes-{}.txt", rand_hex(rng, 6)),
    }
}

/// Generate a decoy file of `kind` in `dir`, embed its honeytoken
/// (registered in `registry`), and return (path, token_id).
pub fn generate_at(
    kind: &str,
    dir: &Path,
    registry: &Path,
) -> Result<(PathBuf, String), String> {
    if !KINDS.contains(&kind) {
        return Err(format!(
            "unknown decoy kind '{}' (kinds: {})",
            kind,
            KINDS.join(", ")
        ));
    }
    let mut rng = rand::thread_rng();
    let content = match kind {
        "credentials" => credentials_content(&mut rng),
        "financial" => financial_content(&mut rng),
        "keys" => keys_content(&mut rng),
        "document" => document_content(&mut rng),
        _ => unreachable!(),
    };
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let mut path = dir.join(filename_for(kind, &mut rng));
    // Never overwrite a real file: if the name is taken, suffix it.
    let mut n = 2;
    while path.exists() {
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "decoy".to_string());
        let ext = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        path = dir.join(format!("{}-{}{}", stem, n, ext));
        n += 1;
    }
    fs::write(&path, content)
        .map_err(|e| format!("cannot write decoy {}: {}", path.display(), e))?;
    let token = honeytoken::embed_token_at(&path, registry, None, true, &format!("decoy:{}", kind))?;
    Ok((path, token))
}

/// Generate a decoy, registering at the configured registry.
pub fn generate(kind: &str, dir: &Path) -> Result<(PathBuf, String), String> {
    generate_at(kind, dir, &honeytoken::registry_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_generates_a_registered_decoy() {
        let dir = std::env::temp_dir().join("ahr-decoy-test");
        let _ = fs::create_dir_all(&dir);
        let reg = dir.join("registry.json");
        for kind in KINDS {
            let (path, token) = generate_at(kind, &dir, &reg).expect(kind);
            assert!(path.exists(), "{} decoy should exist", kind);
            assert_eq!(honeytoken::file_token_at(&reg, &path), Some(token.clone()));
            let entry = honeytoken::lookup_by_path_at(&reg, &path).expect("registry entry");
            assert!(entry.is_decoy, "{} must be registered as a decoy", kind);
            assert_eq!(entry.kind, format!("decoy:{}", kind));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_kind_is_an_error() {
        let dir = std::env::temp_dir().join("ahr-decoy-test-unknown");
        let _ = fs::create_dir_all(&dir);
        let reg = dir.join("registry.json");
        assert!(generate_at("nuclear", &dir, &reg).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decoy_never_overwrites() {
        let dir = std::env::temp_dir().join("ahr-decoy-test2");
        let _ = fs::create_dir_all(&dir);
        let reg = dir.join("registry.json");
        let real = dir.join("passwords.txt");
        fs::write(&real, b"REAL FILE - DO NOT TOUCH\n").unwrap();
        let (path, _) = generate_at("credentials", &dir, &reg).unwrap();
        assert_ne!(path, real, "decoy must not overwrite the real file");
        assert_eq!(
            fs::read_to_string(&real).unwrap(),
            "REAL FILE - DO NOT TOUCH\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
