# ADR 0007: Tamper-evident audit log via per-record hash chaining

- Status: Accepted
- Date: 2026-06-01

## Context

ADR 0002 makes the **service account** — not an internal sandbox — the
trust boundary, and names the append-only audit log as the first of the
compensating controls that make that posture safe to operate. ADR 0003
classifies each call; the audit record is where that classification, the
redacted arguments, and the SHA-256 of the output are committed to disk.
The audit log is therefore the single most security-load-bearing artifact
the project produces: it is the forensic record of everything a persuaded
model (or a compromised client) did through the relay.

Until now the log's integrity rested on two controls, both **outside** the
record itself:

1. **`chattr +a`** (append-only) on the on-disk file, preserved across
   rotation by `deploy/logrotate/relay-shell`.
2. **Off-host shipping** to a SIEM (`docs/audit-shipper.md`), so the
   authoritative copy lives somewhere the relay host cannot reach.

Both are necessary and both are kept. But `SECURITY.md` §"Residual risk"
states plainly that a compromise of the client or transport yields the
capabilities of the service account — and in privileged posture, root.
A root-equivalent attacker can `chattr -a` the file (root holds
`CAP_LINUX_IMMUTABLE`), rewrite or excise lines, and restore the attribute
**in the window before the next shipper flush**. Nothing in the on-disk
record lets a downstream consumer detect that line *N* was edited, that a
run of lines was deleted, or that two records were reordered. The
hash-not-body invariant protects output *confidentiality*; it does nothing
for record-stream *integrity*. That is the gap this ADR closes.

The OWASP Logging Cheat Sheet (a trusted reference in `CLAUDE.md`) calls
for log integrity protection precisely for this threat. The canonical
construction is a hash chain: each record commits to the hash of the one
before it, so any edit, insertion, deletion, or reorder is detectable by
recomputation — even from the shipped copy, after the fact, without
trusting the relay host.

## Decision

Add an **opt-in, additive** per-record hash chain to the audit log.

- **Opt-in, default off.** A new `RELAY_SHELL_AUDIT_CHAIN` setting (default
  `false`) turns it on. When off, the record is **byte-identical** to v0.1:
  no new fields, no new code on the write path, no lock taken. This
  preserves ADR 0002 / 0005 behavior verbatim for every existing deployment.
- **Additive record shape.** When on, each record gains three trailing
  fields and nothing else changes:
  - `seq` — a monotonic integer, 0 at genesis.
  - `prev` — the previous record's `chain` (the 64-zero genesis anchor for
    `seq` 0).
  - `chain` — `SHA-256(prev || canonical(record-without-chain))`, where the
    canonical form is the record serialized with **sorted keys** and compact
    separators so the value is independent of dict insertion order and of
    the on-disk formatter. The existing fields (`ts`, `tool`, `tier`,
    `denied`, `args`, `output_sha256`, `output_len`, `exit_code`,
    `request_id`, `client_id`) keep their meaning and position. Off-host
    parsers built against the current shape keep working; they simply see
    three extra keys.
- **`jsonl` only.** The chain is resumed across restarts and rotation by
  re-parsing the last on-disk record, which is only well-defined for the
  canonical `jsonl` format. `RELAY_SHELL_AUDIT_CHAIN=true` with
  `RELAY_SHELL_AUDIT_FORMAT=cef|leef` is **rejected at startup** (a config
  validation error, fail-fast per the `config` module contract). CEF/LEEF
  target a SIEM that owns integrity on its side.
- **Restart- and rotation-safe.** On construction the logger reads the last
  record and resumes from its `seq + 1` and `chain`. A missing / empty /
  unchained / unparseable tail starts a fresh chain at genesis — a *visible
  seam* (a `seq` reset) that a verifier surfaces, never a silent gap. After
  logrotate moves the file, the in-memory anchor carries the chain into the
  new file unbroken; cross-file continuity is the previous file's last
  `chain` equalling the new file's first `prev`.
- **Ordering invariant under concurrency.** The `seq`/`prev` read-modify-write
  and the line emit are taken under one lock, so the chain stays
  monotonic and correctly linked even if a future caller records from
  another thread (e.g. the ADR 0006 seccomp-notify supervisor). Today every
  write already runs on the single event-loop thread, so the lock is
  uncontended; it is future-proofing, engaged only when chaining is on.
- **Offline verification, no new tool.** A new CLI verb
  `relay-shell --verify-audit [--audit-path PATH] [--json]` walks a file
  and reports `OK` / `BROKEN` (exit 0 / 2), mirroring `--check-config` and
  `--verify-deploy`. It is deliberately **not** an MCP tool: verifying the
  audit trail is an operator/forensic action, not something the audited
  model should drive, and keeping it off the tool surface avoids churning
  the 21-tool contract (`tests/test_server.py::_EXPECTED`). The verifier
  (`audit.verify_chain`) skips any leading legacy records, then requires a
  contiguous valid chain to EOF; a `seq` 0 record must anchor to genesis.

## Consequences

- The audit-record schema grows three optional fields under
  `RELAY_SHELL_AUDIT_CHAIN=true`. Documented in `docs/architecture.md`
  §"Request lifecycle" (step 5) and `docs/runbook.md` §2.3. The default-off
  record is unchanged, so this is purely additive — the same compatibility
  promise ADR 0006 makes for its future `syscall_notify` events.
- `server_info().audit` now reports `format` and `chain` so the runbook §2
  audit pass and an operator can see the live integrity posture without
  re-deriving it from env names.
- The runbook §2.3 "audit-the-audit" step gains a chain-verification check
  (`relay-shell --verify-audit`) when chaining is enabled. The §3.3
  security-sensitive checklist gains the chain fields alongside the existing
  audit-record-field check.
- `docs/audit-shipper.md` is unchanged: the chained record is still one
  JSONL line per call on the same stream the three recipes already tail; the
  three extra keys ride along. A SIEM that re-verifies the chain gains
  end-to-end tamper-evidence from the relay host to the sink.
- Operational guidance: enable chaining on a **freshly rotated** log so the
  chain runs from genesis with no leading legacy prefix. Verify a shipped
  copy with `--verify-audit --audit-path`. Cross-rotation continuity is an
  equality check on the seam (`prev` of file *N+1*'s first record ==
  `chain` of file *N*'s last record), which the verifier prints as the
  start anchor.

## Rejected alternatives

- **HMAC-with-a-secret-key instead of a plain hash chain.** An HMAC keyed by
  a secret the relay does not store on the same host would also defend
  against an attacker *forging* a fresh consistent chain after truncating
  the log (a plain chain lets a root attacker recompute a clean chain over
  doctored records). But it requires a key-management story (where the key
  lives, rotation, the same host holding it to sign means the same
  compromise yields it) that is out of proportion to an opt-in integrity
  aid, and it changes the verification trust model from "anyone with the
  file" to "anyone with the file and the key". The plain chain already
  defeats the dominant threat — *silent in-place edits and excisions that
  the off-host shipper has not yet captured* — because the shipped prefix
  pins every hash the attacker would have to remain consistent with.
  Tamper-*evidence* against a host that does not hold a signing secret is the
  goal; tamper-*proofing* against a key-holding root is explicitly the
  off-host shipper's job, not the on-disk file's. Recorded here so a future
  HMAC/Merkle-anchor extension has a starting point rather than a
  re-litigation.
- **External anchoring (periodic Merkle root to a notary / transparency
  log).** Strongest integrity, but adds a network dependency and a second
  service on the audit hot path — exactly the kind of coupling the
  single-process architecture (ADR 0001) avoids. The hash chain is the
  in-band primitive an external anchor would *build on*; ship the primitive
  first.
- **Rely on `chattr +a` and the off-host shipper alone (status quo).** Both
  are kept, but neither makes a *single altered record* detectable from the
  file, and the shipper has a flush window. The chain is the missing
  in-record evidence.
- **A second `audit.chain` sidecar file of hashes.** Splitting the chain
  from the records makes off-host shipping and forensic correlation harder
  and adds a second file to keep append-only and rotate in lockstep. One
  stream with the hash inline — consistent with how resource-read events
  (`tool="resource:<name>"`) already discriminate on a field rather than a
  file — is simpler and ships for free on the existing pipeline.
- **Chain in CEF/LEEF too.** The chain math is format-independent, but
  *resuming* it across a restart means re-parsing the last record, which is
  clean for `jsonl` and lossy for the SIEM text formats. Rather than emit a
  chain that cannot be reliably resumed (producing genesis seams on every
  restart), the combination is refused at startup. SIEM integrity is the
  aggregator's responsibility in those deployments.

## Validation outcome (2026-06-01)

Implemented and validated in the same PR that lands this ADR (the ADR 0005
four-step pass; full record in `docs/adr/0005-codebase-validation.md`
§"Validation outcome (2026-06-01)" and `audit/2026-06-01-engagement.md`):

- `ruff check`, `ruff format --check`, `mypy --strict` clean. `pytest -q` —
  269 passed, 13 deselected (up from 250; +19 chain/config/CLI tests).
  `pytest -m fuzz` — 13 invariants pass. `coverage` — 92% with subprocess
  collection (floor 90%); `config.py` 99%, `audit.py` 93%.
- 21 MCP tools and 3 resources unchanged — the chain adds a **CLI verb**,
  not a tool, so `tests/test_server.py::_EXPECTED` is untouched.
- Behavior validation: a chained log emits `seq`/`prev`/`chain` with a
  genesis anchor and correct linkage; resumes seq across a simulated
  restart; `verify_chain` returns intact on a clean log and detects edit,
  chain-field forgery, deletion, reorder, a garbage line, a non-genesis
  seq-0 anchor, and a legacy line inside the region; default-off records
  carry none of the three fields (byte-identical to v0.1); and
  `audit_chain=true` with a non-`jsonl` format is rejected at startup. The
  `--verify-audit` CLI returns 0 on an intact chain and 2 once a body is
  edited.

No change to policy admission, tier semantics, the no-sandbox posture, or
any tool's response shape. This pass hardened a compensating control
(ADR 0002's first one); it did not move the trust boundary.
