# AHR Evidence-Plane Threat Model

## Scope
This document covers the cross-host signaling path: `sentinelx.evidence` (NATS)
and any future AHR→AHR control plane. It does NOT cover local process
detection, which is single-host by construction.

## Assets
- A1: Integrity of evidence events (a forged "host X is encrypting" event can
  trigger containment on host X).
- A2: Confidentiality of evidence contents (process names, paths, cwd).
- A3: Availability of the evidence bus (flood = containment lockout).

## Trust boundaries
- B1: Agent process → local NATS client.
- B2: NATS client → NATS server (network).
- B3: NATS server → consuming agents (fan-out).

## Threats (STRIDE-lite)
| ID  | Threat                                   | Mitigation (dev)      | Mitigation (prod, required)              |
|-----|------------------------------------------|-----------------------|-------------------------------------------|
| T1  | Forged evidence event (spoofing)         | none (dev)            | Per-host Ed25519 key; event signed; consumers verify |
| T2  | Replay of old evidence (replay)          | none (dev)            | Monotonic `(host_id, seq)` per signer; consumers reject stale |
| T3  | Evidence leak (info disclosure)          | localhost only        | Subject-scoped ACLs; TLS on NATS; no PII in payload |
| T4  | Evidence flood (DoS)                     | none                  | Per-host rate limit; consumers backpressure; server-level subject quotas |
| T5  | Consumer impersonation (spoofing)        | none                  | Mutual TLS or NKey per consumer |
| T6  | Silent key compromise (repudiation)      | none                  | Key rotation policy; audit log of key use |

## Current status (2026-11-26)
- Dev scaffold: **unauthenticated NATS on localhost**. Acceptable ONLY for
  `docker run --rm -p 4222:4222 nats:latest` on a laptop.
- Production readiness for cross-host signaling: **NOT CLAIMED**. T1–T6 are
  all open. Do not deploy AHR across a trust boundary until T1, T2, T5 are
  closed.

## Invariants the agent MUST preserve regardless of transport
1. Local decisions never depend on remote evidence alone. A remote "contain
   host X" event MUST be re-scored locally before action.
2. Evidence events are append-only observations, never commands. The control
   plane is a *recommendation*, not an RPC.
3. A failed signature verification on an evidence event is an audit-worthy
   event, not a dropped message.
