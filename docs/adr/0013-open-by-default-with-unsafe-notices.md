# ADR 0013: Open by default, with notices about what is unsafe

- Status: Accepted
- Date: 2026-10-14

## Context

relay-shell is an operator tool: its job is to let a trusted MCP client run any command on
the local host and on SSH targets, with a tier classifier and an audit log beside it. The
policy layer (ADR 0003) has three modes. `open` admits everything and only classifies and
audits; `guarded` and `readonly` narrow the envelope. The shipped default was already
`open`, with an empty deny list and the Tier-3 confirmation broker (ADR 0009) off, but that
was a fact scattered over several documents, nothing pinned it, and the only feedback to a
caller about risk was a tier number in the audit log it may never read. An operator who
wants the server to "just run it" had to infer that, and a caller that ran `rm -rf` got
`[exit 0]` with no sign that the server had judged the command irreversible.

The request behind this ADR (2026-10-14, repository owner): no command is blocked by
default, relay-shell can do everything, and it tells the caller what is unsafe. Per
`AGENTS.md` a posture change needs explicit scope and design review; this ADR is that
record, and the request is the scope.

## Decision

1. **Open is the contract, and it is tested.** With the default configuration
   (`RELAY_SHELL_POLICY_MODE=open`, no `RELAY_SHELL_POLICY_DENY`, no
   `RELAY_SHELL_POLICY_ALLOW`, `RELAY_SHELL_CONFIRM_TIER3` off) the policy layer admits every
   command on every tool. `tests/test_notices.py` pins the defaults and runs a corpus of
   commands people consider dangerous (`rm -rf /`, `mkfs`, `dd` to a block device, `shutdown`,
   `curl | sh`, `sudo ...`) through `Policy("open")`. Refusal remains available and opt-in:
   `guarded`, `readonly`, a deny list, and the confirmation broker. The deny list is still
   enforced first in every mode (ADR 0003, unchanged).
2. **The caller is told.** A call that was admitted and ran as Tier 2 or Tier 3, or with
   SSH host-key verification off, gets one or two trailing lines in its result:
   `[NOTICE tier 3 (IRREVERSIBLE), matched an irreversible-operation pattern. It may not
   be undoable and ran with no confirmation step; ... Classification is a heuristic, not a
   boundary]`. `policy.assess()` returns the tier together with the basis that produced it
   (`BASIS_*` strings), and `PolicyDecision.basis` carries it to the runner. A tool whose
   result is a JSON object (`ssh_fanout`) carries the notices in a `"notices"` array inside
   the object, so the result still parses. `ssh_check` and `ssh_fanout` resolve their targets
   inside the work, so they pass the hosts that would be dialled with host-key checking off
   (server default or inventory entry) as extra notices. Tier 0 and 1 calls get nothing unless
   they dial a host with verification off, so a notice keeps its meaning. `RELAY_SHELL_UNSAFE_NOTICES=false`
   turns the lines off.
3. **The audit record does not change.** The record is written from the same `final` text as
   before the notice is appended, so `output_sha256` and `output_len` describe the command's
   output, not the notice. The tier is already in the record. Nothing the notice says is
   evidence; it is a message to the caller.
4. **The standing posture is reported.** `server_info` gains `warnings`, a list built by
   `notices.config_warnings()` from the settings (running as root, open policy without a deny
   list or confirmation, `ssh_known_hosts` of `accept-new` or `ignore`, per-call weaker host
   keys allowed, HTTP without OAuth, audit chain off). The same list is logged at startup and
   printed by `--check-config`. An empty list is not a security statement.
5. **What still refuses a call, honestly listed.** These are resource bounds and startup
   checks, not policy, and each has a setting: `RELAY_SHELL_MAX_INPUT` (a call whose command,
   stdin, script and env exceed it is refused rather than scanned partially, because the scan
   is synchronous), `RELAY_SHELL_MAX_TIMEOUT` (a command is killed at the clamped timeout;
   long work belongs in `shell_spawn`/`ssh_spawn`), `RELAY_SHELL_MAX_SESSIONS` and
   `RELAY_SHELL_MAX_FORWARDS`, the output cap (truncation, not refusal), and the startup
   refusal of an unauthenticated non-loopback HTTP listener unless
   `RELAY_SHELL_ALLOW_UNAUTH_NETWORK=true`.

Rejected alternatives: **no change** (leaves the posture implicit and the caller uninformed);
**a warning field in a structured result** (the tools return text, and every client already
reads the tail of it; a new envelope would break clients that parse `[exit N]`);
**a leading notice** (breaks clients that match the `[exit N]` prefix); **blocking by
default with a documented override** (contradicts the request, and a classifier that is
heuristic would give a false sense of containment); **notices on Tier 1** (a notice on
nearly every call would carry no information).

## STPA analysis

### Purpose, boundary, stakeholders

Purpose: a caller can run any command and knows, at the moment it runs, when the command or
the server's configuration carries risk the caller has not been told about. Boundary: the
runner (`Relay.run`), the policy layer, `server_info` and the startup path. The target
hosts, the MCP client's own judgement and the operator's backups are outside it.
Stakeholders: the operator, the MCP client (human or model), the owners of the target hosts.

### Losses and hazards

- L-1 A destructive command runs without the caller or operator having recognised it as one.
- L-2 The operator believes a stricter mode is active when it is not (false assurance).
- L-3 A notice or warning is taken as a guarantee that unflagged commands are safe.
- H-1 An admitted Tier 2/3 call returns no indication of its classification.
- H-2 `server_info` describes a stricter posture than the one in force.
- H-3 The classifier's verdict is presented as a containment boundary.
- H-4 The notice path changes what is audited, or can fail a call.

### Safety constraints

- SC-1 (H-1) Every admitted call classified Tier 2 or above carries a notice unless the
  operator switched notices off.
- SC-2 (H-2) `warnings` is computed from the live `Settings`, never from a cached or
  documented value.
- SC-3 (H-3, L-3) Every notice and warning says the classification is a heuristic, and the
  documentation states that a command without a notice is not thereby safe.
- SC-4 (H-4) The notice is appended after the audit record is written and cannot raise: it
  is a pure function of the decision and the already-redacted audit arguments.
- SC-5 (L-2) The default posture is pinned by a test, so a change to a default is a visible
  diff.

### Control structure

Controller: the policy layer (admit or refuse). Controlled process: the executor that runs
the command. Control actions: admit, refuse, mint a confirmation token. New feedback path:
the notice to the MCP client, and `warnings` to the operator. Process model of the caller:
"the server refuses what it considers unsafe" is replaced by "the server runs what it is
asked and says what it considers unsafe".

### Unsafe control actions

| ID | Type | Unsafe control action | Constraint |
|----|------|----------------------|------------|
| UCA-1 | Not provided | An admitted irreversible command returns no notice | SC-1 |
| UCA-2 | Provided unsafely | A notice is attached to a denied call, implying it ran | SC-1 (denials return `[DENIED ...]` only) |
| UCA-3 | Provided unsafely | The notice alters the audited output or its hash | SC-4 |
| UCA-4 | Not provided | `server_info` omits a permissive setting | SC-2 |
| UCA-5 | Provided unsafely | The absence of a notice is read as a safety verdict | SC-3 |
| UCA-6 | Too late | The notice arrives after the caller has already issued a dependent command | Accepted: the command has already run; the notice informs the next decision |

### Causal scenarios

- CS-1 (UCA-1) A destructive command written so the regexes miss it (quoting, `eval`,
  `base64 -d | sh`). No notice. Residual and by design: the classifier is not a shell
  parser. The tests for the covered forms are `tests/test_notices.py` and
  `tests/test_classifier_v16.py`; fuzz tests bound regex cost only.
- CS-2 (UCA-3) A future change formats the notice into `final` before the record. Test:
  `test_a_notice_does_not_change_the_audit_record` hashes the body without the notice.
- CS-3 (UCA-4) A new permissive setting is added without a warning. Mitigation: review
  checklist item in `docs/runbook.md` for new settings; no automated check.
- CS-4 (UCA-5) A model learns that "no notice" means "safe". Mitigation: the wording of the
  notice and the tool guidance both say the classifier is a heuristic.
- CS-6 (UCA-3) A notice appended after a JSON result makes `json.loads` fail after the remote
  command already ran, so a caller retries a mutation. Addressed by `attach_notices(...,
  as_json=True)` for `ssh_fanout`. Test: `test_fanout_keeps_its_json_and_carries_the_notices_inside_it`.
- CS-5 (UCA-2) A refused call was shown with a notice. Test:
  `test_a_blocked_call_is_not_a_notice_it_is_a_denial`.

### Assumptions and limits

The analysis assumes the MCP client reads the tail of a tool result. A client that
truncates or discards it gets no feedback; the audit record is still complete. The notice is
text produced by the server and carries no authority. This is not a safety certification.

## Threat analysis

Trust boundary: MCP caller to executor. Removing refusals by default does not add a path:
`open` was already the default, and the controls that exist for an untrusted caller
(authentication, the deny list, `guarded`/`readonly`, the confirmation broker, audit) are
unchanged. The notice adds output text; the audit-argument redaction already ran on the data
it reads (only `known_hosts` is consulted), and the notice contains no command text, so it
cannot leak a secret. STRIDE: information disclosure is not widened; repudiation is not
affected because the record is unchanged; no new elevation path.

## Consequences

- Clients see up to two extra trailing lines on Tier 2/3 results. A client that matched the
  whole result against a fixed string must tolerate the suffix or set
  `RELAY_SHELL_UNSAFE_NOTICES=false`.
- Operators who want refusal keep it: set `RELAY_SHELL_POLICY_MODE=guarded` (with an
  allow-list) or `readonly`, a deny list, and `RELAY_SHELL_CONFIRM_TIER3=true`.
- Tests: `tests/test_notices.py`; the notice is exercised through the real tool wrappers.
- Rollback: revert the commit, or set `RELAY_SHELL_UNSAFE_NOTICES=false` to silence the
  notices without a code change.
