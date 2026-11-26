# Evidence-plane test data

Sample evidence events for the cross-host signaling path
(`sentinelx.evidence`), one fixture per threat in
`docs/evidence-plane-threat-model.md` that an event document can
demonstrate. See `manifest.json` for the mapping, the expected
verdict per fixture, and the assumptions (placeholder signatures,
assumed 100 events/host/second flood limit, fixed timestamps).

Layout:

- `valid-event.json` — the control case: well-formed, in-sequence.
- `forged-event.json` — T1, bad signature.
- `replayed-event.json` — T2, stale sequence number.
- `pii-leak-event.json` — T3, personal paths inside free-text reasons.
- `flood-burst.jsonl` — T4, 120 events from one host in one second.
- `rotated-key-event.json` — T6, new key after rotation, seq restarts.

T5 (consumer impersonation) is a transport property and has no
event fixture.

## Shape

Each file is `{"envelope": {...}, "event": {...}}`. The `event`
object matches `EvidenceEvent` in `src/sentinel.rs` exactly. The
`envelope` (`host_id`, `seq`, `key_id`, `signature`) is the shape
the threat model requires for production and is **not yet
implemented in the agent** — the dev scaffold emits the bare event
on unauthenticated NATS. Signature values here are placeholder
strings, not real Ed25519 signatures.

## How it is exercised

`tests/evidence_fixtures.rs` loads `manifest.json` and checks every
listed fixture parses, carries the required envelope and event
fields, and that the flood file has the declared line count. It
checks structure only — it does not verify signatures, because
there is no verifier yet. When T1/T2/T5 close, the fixtures become
the verifier's input corpus.
