//! Evidence-plane fixtures: structure checks only.
//!
//! Loads testdata/evidence/manifest.json and verifies every listed
//! fixture parses and carries the required envelope and event fields.
//! This checks the test data itself, not signatures or verification:
//! there is no verifier yet (threat model T1/T2/T5 are open), and the
//! fixture signatures are placeholders. When the verifier lands, these
//! files become its input corpus.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn testdata_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/evidence")
}

const ENVELOPE_FIELDS: [&str; 4] = ["host_id", "seq", "key_id", "signature"];
const EVENT_FIELDS: [&str; 13] = [
    "event_type",
    "ts_unix",
    "pid",
    "process_name",
    "process_hash",
    "threat_index",
    "severity",
    "anomaly_score",
    "score_reasons",
    "mitre_ttp",
    "recommended_action",
    "executed_action",
    "requires_human_review",
];

fn check_event_doc(doc: &Value, file: &str) {
    let env = doc
        .get("envelope")
        .unwrap_or_else(|| panic!("{file}: missing envelope"));
    for f in ENVELOPE_FIELDS {
        assert!(env.get(f).is_some(), "{file}: envelope missing {f}");
    }
    let ev = doc
        .get("event")
        .unwrap_or_else(|| panic!("{file}: missing event"));
    for f in EVENT_FIELDS {
        assert!(ev.get(f).is_some(), "{file}: event missing {f}");
    }
    let sev = ev["severity"].as_str().unwrap_or("");
    assert!(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"].contains(&sev),
        "{file}: bad severity {sev}"
    );
    let ti = ev["threat_index"].as_u64().unwrap_or(100);
    assert!(ti <= 99, "{file}: threat_index {ti} out of range");
}

#[test]
fn manifest_fixtures_are_well_formed() {
    let dir = testdata_dir();
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(dir.join("manifest.json")).expect("read manifest.json"),
    )
    .expect("manifest.json parses");
    let fixtures = manifest["fixtures"]
        .as_array()
        .expect("manifest has a fixtures array");
    assert!(!fixtures.is_empty(), "manifest lists no fixtures");
    for fx in fixtures {
        let file = fx["file"].as_str().expect("fixture has a file");
        let threat = fx["threat"].as_str().unwrap_or("");
        let expected = fx["expected"].as_str().unwrap_or("");
        assert!(!threat.is_empty(), "{file}: manifest missing threat");
        assert!(!expected.is_empty(), "{file}: manifest missing expected verdict");
        let path = dir.join(file);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{file}: {e}"));
        if file.ends_with(".jsonl") {
            let want = fx["lines"].as_u64().expect("jsonl fixture declares lines");
            let mut count = 0u64;
            for (i, line) in text.lines().enumerate() {
                let doc: Value =
                    serde_json::from_str(line).unwrap_or_else(|e| panic!("{file} line {i}: {e}"));
                check_event_doc(&doc, &format!("{file} line {i}"));
                count += 1;
            }
            assert_eq!(count, want, "{file}: expected {want} lines, got {count}");
        } else {
            let doc: Value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
            check_event_doc(&doc, file);
        }
    }
}
