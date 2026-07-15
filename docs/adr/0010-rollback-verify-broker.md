# ADR 0010: Rollback / verify pairing for the confirmation broker (BRK-2)

- Status: Proposed
- Date: 2026-07-15

## Context

[ADR 0009](0009-tier3-confirmation-broker.md) added an opt-in, default-off
**two-step confirmation broker** for Tier-3 (IRREVERSIBLE) operations: a
Tier-3 call returns a single-use, TTL-bounded token instead of running, and a
distinct `operation_confirm(token)` arm step plus a re-issue of the exact same
call is required to execute. ADR 0009 explicitly **deferred** the other half of
the sibling brokers it drew from — pairing an operation with a **rollback
command**, a **post-execution verify command**, and an **auto-rollback** on
verify failure — as a materially larger surface needing its own ADR
(runbook §7.1, BRK-2). This is that ADR.

The pattern, as the sibling planes implement it: a destructive action is
submitted together with (a) a `verify_command` that checks the system reached
the intended state and (b) a `rollback_command` that undoes the action; after
execute, the broker runs verify, and if `auto_rollback` is set and verify
fails, runs rollback — a small orchestrated control loop of up to three
commands under one authorization.

The problem it *would* solve for `relay-shell`: an **unattended / autonomous**
Tier-3 operation where no human or second agent is watching to react if the
operation half-succeeds. A migration that leaves a service down, a
`dd`/`mkfs`/`rm` that partially applies — today the model that issued it must
itself notice and remediate. Rollback/verify binds the remediation to the
operation *up front*, so it runs even if the issuing turn never follows through.

Weighed honestly, that value is narrow, and the cost is not. Everything below
is why this ADR's decision is to **specify the design but keep it deferred**,
with explicit triggers that would move it to Accepted.

## Decision

**Defer BRK-2.** Do not build the rollback/verify pairing now. Keep this ADR
`Proposed` as the design of record, and adopt it (status → `Accepted`, with an
implementing PR) only when a **trigger** below is real. When built, it must
satisfy the **invariants** below — they are the reason it is not a small change.

### Triggers that would justify building it

Adopt when at least one is concretely true, not hypothetical:

1. A supported **autonomous / unattended** deployment exists (a scheduled or
   agent-driven run with no human and no second agent in the loop to react to a
   failed Tier-3 op) — the one setting where binding remediation up front beats
   letting the issuing turn remediate.
2. Operators ask for **operation-bound remediation** that survives the issuing
   turn (an audited guarantee that "if this migration's verify fails, this
   rollback runs") that the model sequencing three calls itself cannot provide.
3. A post-incident review shows a real half-succeeded Tier-3 operation whose
   blast radius a bound auto-rollback would have contained.

Absent a trigger, the marginal value over what already ships is low: a model in
control can already sequence *operation → verify → rollback* as three ordinary,
individually policy-checked, individually audited tool calls. The **only** thing
the broker adds is that the remediation is *bound and automatic* — which
matters exactly and only when the issuing actor will not do it, and an actor
that issued a destructive op and refuses to remediate is the residual-risk
attacker ADR 0002/0009 already state is **out of scope**. Building the machinery
before a trigger spends real surface for a benefit the current design already
covers in the attended case.

### Invariants any implementation MUST satisfy

If a trigger fires, the pairing is admissible only if it holds all of these.
They are the design constraints, and collectively the reason this is a v2, not
a parameter:

1. **Opt-in, default-off, byte-identical when off.** Gated behind its own flag
   (e.g. `RELAY_SHELL_CONFIRM_ROLLBACK`, requiring `RELAY_SHELL_CONFIRM_TIER3`).
   When off, no new audit fields, no behavior change — the same promise ADR
   0006/0007/0009 keep.

2. **Rollback and verify are themselves fully policy-gated commands.** They are
   commands, not trusted broker internals. Each MUST pass through the *same*
   central `Relay.run` admission — deny list first, mode check, tier
   classification — as any other call. A rollback that is itself Tier 3 (undoing
   `rm` by restoring from backup could be) is classified and admitted as Tier 3.
   **No path may let a rollback/verify string skip the deny list**; that would
   turn the remediation channel into a policy-bypass primitive. This is the
   single most important invariant and the hardest to get right.

3. **Bound into the confirmation identity.** ADR 0009 binds a token to
   `sha256(tool \0 op_key)` where `op_key = policy_text \0 canonical(audit_args)`.
   The rollback and verify command text MUST fold into that binding (extend
   `op_key`), so a token armed for `(op, rollback_A, verify_A)` cannot execute
   with `rollback_B` — the same confused-deputy defense ADR 0009's BRK-3
   follow-up established for SSH identity. The commands must be fixed at **plan**
   time and surfaced in the `confirm_plan` audit record, never swappable at
   execute.

4. **Distinct, complete audit records.** Execute, verify, and rollback are three
   separate audited operations, each with its own tier, exit code, and hashed
   output (ADR 0007), distinguished by new `action` values
   (`confirm_execute` unchanged; add `confirm_verify`, `confirm_rollback`). The
   optional-field discipline (written only when non-empty) keeps default-off
   byte-identical. An auto-rollback that fires is the loudest possible line in
   the trail, never a silent correction.

5. **Bounded, terminating, non-recursive control loop.** At most one verify and
   one rollback per confirmed operation. Rollback failure does not trigger a
   further rollback. Verify/rollback carry their own timeouts (clamped to
   `max_timeout` like every executor) so the loop cannot hang the runner, and a
   rollback is **never** itself gated behind a *new* confirmation token (that
   would deadlock the remediation on a second arm step).

6. **Fail-safe on partial state.** If the process dies mid-loop (after execute,
   before verify/rollback), the system is in the post-execute state with the
   plan on the audit trail — the same fail-safe posture as a bare ADR 0009
   execute. No persisted rollback promise (a persisted "run this command later"
   is a replay/again-execution surface strictly worse than the ephemeral token
   ADR 0009 already argued for).

7. **Verify defines failure explicitly.** "Verify failed" must be a precise,
   documented predicate (non-zero exit, or an operator-supplied expected-output
   match) — not a heuristic — because it is the trigger for *executing another
   command automatically*. Ambiguity here is a footgun that auto-runs a rollback
   on a spurious signal.

### Shape (illustrative, not binding until built)

Under the trigger, the least-surface realization is an **extension of
`operation_confirm`**, not new top-level tools: the arm step optionally carries
`verify_command`, `rollback_command`, and `auto_rollback`, which the broker
stores against the token (folded into `op_key` per invariant 3). On the bound
re-issue, the runner executes the main op (`confirm_execute`), then — if
supplied — runs verify via the same central runner (`confirm_verify`), and on a
failing verify with `auto_rollback` set, runs rollback (`confirm_rollback`).
Keeping it on `operation_confirm` preserves ADR 0009's "central gate, no
per-wrapper param" property and adds no new tool to the contract.

## Consequences

- **If deferred (this ADR's decision):** no code, no new tool, no audit-shape
  change. The backlog item (runbook §7.1 BRK-2) points here for the design and
  the triggers; the vague "needs an ADR" is replaced by a concrete
  decision-with-conditions. Reviewers and operators have a written answer for
  "why doesn't the broker roll back?" — it can, the design is specified, and the
  cost/benefit says wait for a trigger.
- **If later adopted:** a new opt-in flag, up to two new `action` values, an
  extended `operation_confirm`, broker state carrying the bound commands, and
  the runbook §3.3 security-sensitive invariant list gains the seven above. The
  tool contract count is unchanged (extension, not a new tool). ADR 0009's
  validation battery is re-run plus new cases: verify-fail→auto-rollback,
  rollback-is-Tier-3-and-still-policy-gated, deny-list-still-blocks-a-rollback,
  token-bound-to-the-rollback-text, and process-death-mid-loop fail-safe.
- **Trust boundary unchanged either way.** Like ADR 0009 this is a compensating
  control layered on ADR 0003 classification; it does not move the ADR 0002
  boundary, and (invariant 2) it must never become a way around the deny list.

## Rejected alternatives

- **Build it now, alongside ADR 0009.** ADR 0009 explicitly rejected this to
  land the confirmation gate cleanly first; nothing since has produced a
  trigger, so bundling it would add the largest-surface broker feature
  speculatively. Rejected until a trigger is real.
- **Rollback/verify as free-form broker-executed strings, admitted once with
  the main op.** Lets the remediation commands skip their own deny-list/tier
  check (they'd ride the main op's single admission). This is the tempting
  shortcut and it is a policy-bypass hole — it violates invariant 2. Rejected.
- **New top-level `rollback_command` / `verify_command` tools.** More surface,
  and it invites callers to run rollback/verify *unbound* from any operation
  (just more Tier-N tools), which is simply the model sequencing calls it can
  already do — with none of the binding that is the feature. Rejected in favor
  of extending `operation_confirm` (invariant/shape above).
- **Persist the rollback promise across restarts.** A stored "run this later"
  is a re-execution/replay surface; ADR 0009 already argued ephemeral,
  process-local state is safer. The fail-safe (invariant 6) is post-execute
  state plus the audit trail, not a durable rollback queue. Rejected.
