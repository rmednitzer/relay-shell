# ADR 0009: Opt-in two-step confirmation broker for Tier-3 operations

- Status: Accepted
- Date: 2026-07-15

## Context

ADR 0002 makes the **service account** — not an internal sandbox — the trust
boundary, and ADR 0003 classifies every call into a tier. The compensating
controls that make the unsandboxed posture safe to operate are *audit, tiered
policy, redaction, and resource bounds*. Today the tiered policy is a
**single-pass** admission decision (`policy.Policy.check`): the deny list runs
first in every mode, then the mode narrows the envelope —

- `open` (the documented default): everything is permitted but classified and
  audited;
- `guarded`: refuses Tier 2+ unless `RELAY_SHELL_POLICY_ALLOW` matches;
- `readonly`: permits only Tier 0.

That leaves a gap for the highest-consequence class. A **Tier 3
(IRREVERSIBLE)** operation — `rm -rf`, `mkfs`, `dd of=/dev/…`, a destructive
`>` redirect — in the default `open` posture executes on first request with no
friction at all. `guarded` can refuse it wholesale, but that is all-or-nothing:
an operator who legitimately needs occasional irreversible admin work must
either run `open` (no gate) or maintain a `POLICY_ALLOW` regex. There is no
*"permit, but require a deliberate second step for this specific irreversible
call"* middle ground.

This pass compared `relay-shell` against two sibling MCP control planes. The
authoritative pattern there is a **plan → authorize → execute** operation
broker: a privileged or destructive action is not run when first requested; it
returns a single-use, TTL-bounded authorization token, and only a distinct
second call that presents the token proceeds to execution. That extra step is
exactly the friction missing here: it forces a model persuaded within a single
turn to take a separate, auditable action before an irreversible command runs.
This ADR adapts that pattern into `relay-shell`'s idiom.

## Decision

Add an **opt-in, additive** two-step confirmation broker for Tier-3 operations,
enforced in the one central runner (`Relay.run`) so it covers every tool
uniformly.

- **Opt-in, default off.** A new `RELAY_SHELL_CONFIRM_TIER3` setting (default
  `false`) turns it on; `RELAY_SHELL_CONFIRM_TTL` (default 120s, range 5–3600)
  bounds token lifetime. When off, `Relay.broker` is `None`, the gate block is
  skipped entirely, and the audit record is **byte-identical** to today — the
  same compatibility promise ADR 0006/0007 make. This preserves ADR 0002/0005
  behavior verbatim for every existing deployment.

- **A safeguard on top of policy, never a bypass.** The deny list and mode
  check in `Relay.run` run **first**, unchanged. The broker gate is consulted
  only *after* a call is already admitted, and only when
  `decision.tier == Tier.IRREVERSIBLE`. Confirmation never widens what policy
  allows; it only adds friction to what policy already permits. A denied call
  is still denied; a `readonly`/`guarded`-refused Tier-3 call never reaches the
  broker.

- **Bound to the exact operation, not a per-tool parameter.** A token is bound
  to `sha256(tool \0 op_key)`, where `op_key` is built in `Relay.run` from the
  command/content probe (`policy_text`) **and** a canonical serialization of the
  full audited argument set (`audit_args`). `policy_text` fixes *what* runs
  (command + stdin + env + script body, via the `_policy_text_*` builders);
  `audit_args` fixes the operation's *target* — the `host` (SSH tools), `hosts`
  (`ssh_fanout`), `cwd` (shell tools), `session_id` (`session_send`),
  `local`/`remote` (transfer tools) — which `policy_text` deliberately omits.
  Binding to both means a token armed for one target cannot be consumed against
  another (no confused-deputy replay), and the gate is correct for every current
  *and future* Tier-3-capable tool with **no per-wrapper token threading** and
  no risk of a new tool silently escaping the gate. It lives in exactly one
  place, mirroring how the deny list and classifier already gate centrally.

- **The flow (three audited steps on the normal stream).**
  1. **plan** — a Tier-3 call with no armed confirmation returns
     `[CONFIRM REQUIRED tier 3 …: call operation_confirm(token="…") then
     re-issue this exact call within Ns.]` and is audited with
     `action=confirm_plan`. `work()` does **not** run — no side effect.
  2. **arm** — a new `operation_confirm(token)` MCP tool marks that token
     armed. It is Tier 0 (it mutates only ephemeral broker state and authorizes
     nothing on its own) and its audit record carries only a non-replayable
     token *fingerprint*, never the raw token.
  3. **execute** — re-issuing the *exact* same call finds the armed token,
     burns it (single-use), and proceeds to `work()`; the executed record is
     tagged `action=confirm_execute`.

- **Additive record shape.** The audit record gains one optional `action`
  field, written only when non-empty (exactly like `request_id`/`client_id`).
  Off-host parsers keep working; a default call and the whole default-off
  configuration produce a byte-identical record. `server_info` gains a
  `confirm` block (`tier3`, `ttl`, live `pending` count) so an operator sees
  the live posture without re-deriving it from env names.

- **Ephemeral, process-local state.** Tokens live in an in-memory,
  lock-guarded, size-bounded, TTL-swept store. A restart drops all pending
  tokens — fail-safe, since a dropped token simply re-plans — so there is
  nothing to persist and no cross-restart replay. The lock future-proofs
  against a second writer (e.g. the ADR 0006 supervisor thread), matching the
  audit logger's posture; today every caller runs on the event loop.

- **A tool, not a CLI verb (contrast ADR 0007).** Unlike audit verification —
  an operator/forensic action deliberately kept *off* the tool surface — the
  confirm step is part of the model's own workflow: the model that issued the
  Tier-3 call is the actor that must take the deliberate second step. So
  `operation_confirm` is a registered MCP tool, moving the contract from 21 to
  **22 tools** (`tests/test_server.py::_EXPECTED`, `docs/tools.md`, README, and
  `_INSTRUCTIONS` updated in lockstep).

## What the confirmation gate provides (and what it does not)

It provides **deliberate, audited friction** for irreversible operations: an
irreversible command cannot run as an unbroken continuation of a single
request; a separate `operation_confirm` call, bound to that exact operation and
valid only briefly, must intervene, and both the intent (`confirm_plan`) and
the execution (`confirm_execute`) are on the audit trail.

It is **not** a capability reduction and not a sandbox. A client fully in
control can call `operation_confirm` itself and proceed — the value is that
doing so is a *distinct, logged, deliberate* act rather than an implicit one,
raising the bar against single-turn persuasion and leaving clearer forensics.
It does not defend against a client that has already decided to destroy data
and will take both steps; that residual risk is the same ADR 0002 posture,
unchanged. Tier classification is heuristic (ADR 0003): the gate is only as
precise as the tier, so it is an *additional* guardrail layered on the deny
list, never a replacement for it.

## Consequences

- The audit-record schema grows one optional `action` field under
  `RELAY_SHELL_CONFIRM_TIER3=true`; documented in `docs/architecture.md`
  §"Request lifecycle" and `docs/runbook.md` §2.3. Default-off is byte-identical.
- `Relay.run` gains one gate block, skipped when the broker is `None`. The
  §3.3 security-sensitive checklist (runbook) gains the broker invariants
  (opt-in, default-off byte-identical, deny/mode-first, single-use/TTL,
  raw-token-never-logged).
- One new tool (`operation_confirm`) and one new module (`broker.py`, paired
  with `tests/test_broker.py`). `server_info` reports the live `confirm` block.
- The `inc_tool_call` metric gains a bounded `confirm_required` outcome value
  (a fixed constant, never user-controlled — the label-cardinality invariant
  holds).

## Rejected alternatives

- **Thread a `confirm` token through every Tier-3-capable tool wrapper.** Gives
  a two-call flow (no separate `operation_confirm`), but requires editing ~11
  wrappers and — worse — creates a standing correctness footgun: any future
  tool that can classify Tier 3 but forgets the parameter would be permanently
  un-confirmable (fail-closed but broken) when the broker is on. The central
  gate is correct-by-construction for every tool, present and future, which for
  a security control outweighs saving one round-trip.
- **Make it a new policy *mode* (e.g. `confirm`).** Modes are a total order
  over tiers; confirmation is orthogonal (it can apply within `open` or
  `guarded`). Folding it into the mode enum would conflate "how much is
  permitted" with "what needs a second step" and complicate the four other
  places that switch on mode. A separate opt-in flag composes cleanly with any
  mode.
- **Rollback / verify commands (`rollback_command`, `verify_command`,
  `auto_rollback`) now.** The sibling broker also pairs an operation with a
  rollback and a post-verify command. That is a materially larger surface
  (executing *more* commands on the audited path, with their own policy/audit
  implications) and is deferred to the backlog (runbook §7.1) as a v2 built on
  this gate, rather than scoped into the same change. This ADR delivers the
  confirmation gate cleanly first.
- **Persist tokens across restarts.** Unnecessary and worse: a persisted token
  is a replay surface, and losing pending tokens on restart is already
  fail-safe (re-plan). Ephemeral, process-local state is the simpler and safer
  choice.

## Validation outcome (2026-07-15)

Implemented and validated in the same PR that lands this ADR (evidence in
`audit/2026-07-15-engagement.md`):

- `ruff check`, `ruff format --check`, `mypy --strict` clean. `pytest -q` —
  **391 passed / 13 deselected** (up from 374; +17 broker/wiring tests).
  `pytest -m fuzz` — 13 invariants pass. `coverage` — **94%** with subprocess
  collection (floor 90%); `broker.py` **100%**, `server.py` 96%.
- **22** MCP tools (was 21): `operation_confirm` added; `_EXPECTED`, the stdio
  e2e count, `docs/tools.md`, README, and `_INSTRUCTIONS` updated in lockstep.
- Behavior validation: default-off Tier-3 runs unchanged and the record carries
  **no** `action` field (byte-identical); enabled, a Tier-3 call is challenged
  (`confirm_plan`, no side effect — a target file survives the plan step),
  arming then re-issuing the exact call executes it (`confirm_execute`, the
  target is removed), a mismatched/expired/bad token re-challenges, a non-Tier-3
  call is unaffected, and the raw token never appears in the audit log.

### PR-review hardening

A security review of the diff (bundled `/security-review`) caught one HIGH:
the initial draft bound the token to `sha256(tool \0 policy_text)` only. Because
`policy_text` is the *command-content* probe and deliberately omits the target
(`host`, `cwd`, `session_id`, `hosts`), a token armed for one target could be
consumed against another — confirm `cwd=/tmp` then execute `cwd=/`, or confirm
one host then fan `ssh_fanout` out to the whole inventory — defeating the gate's
own "bound to the exact operation" promise. The fix widened the binding to
`op_key = policy_text \0 canonical(audit_args)` (`_confirm_op_key` in
`server.py`), since `audit_args` carries the target for every tool; the central
gate keeps the no-per-wrapper-param property. A regression test
(`test_on_token_bound_to_target_not_just_command`) pins that a token armed for
one `cwd` neither authorizes nor mutates a different `cwd`. Connection-only
modifiers that are not in the audit record (`user`/`port`/`key_path` for the SSH
tools) are not part of the binding: they change *how* the relay connects, not
*what* audited operation runs against *which* target, so a change to them alone
(same host + same command) is out of scope for the confirmation identity.

### 2026-07-15 follow-up: SSH identity folded into the binding (BRK-3)

The adversarial pass (`audit/2026-07-15-adversarial-engagement.md`) reversed the
"out of scope" call above. A concrete escalation makes it matter: confirm
`ssh_exec(host, "DROP DATABASE prod", user=readonly)`, arm, then re-issue with
`user=root` — same host+command, so the op-key matched and the token was
consumed against the escalated credential, invisible in the `confirm_plan`
record. The fix adds `user`/`port`/`key_path` to the `ssh_exec`/`ssh_spawn`
audit_args, which (since the op-key hashes `audit_args`) folds them into the
binding **and** surfaces the credential in the audit trail — a strictly better
outcome than the original scoping. Pinned by
`test_confirm_op_key_binds_ssh_identity`.

No change to policy admission, tier semantics, the no-sandbox posture, or any
existing tool's response shape. This pass added a compensating control layered
on ADR 0003's classification; it did not move the trust boundary.
