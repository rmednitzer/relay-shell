# ADR 0015: Operator approval of Tier-3 confirmations with SSH signatures

- Status: Accepted
- Date: 2026-11-23

## Context

ADR 0009 added an opt-in plan, arm, execute handshake for Tier-3 (IRREVERSIBLE)
calls. The arm step is the `operation_confirm` MCP tool, called by the client
that received the token. ADR 0009 says so plainly: "a client fully in control can
call `operation_confirm` itself and proceed". The gate is friction against
single-turn persuasion, not a human approval.

The 2026-11-23 comparison with the Vertex control plane found the same gap there
(Vertex ADR-011: "the digest is not human approval") and a deployment where it
matters: the production relay runs with `RELAY_SHELL_CONFIRM_TIER3=true`, so it
pays for the extra step without getting a human in the loop. MCP tool annotations
(`operation_confirm` advertised as not read-only, PR #298) make a client prompt
more likely, but only on clients that honour annotations.

The obvious fix, an operator verb on the relay host (`relay-shell --confirm
<id>`, or a marker file the server reads), does not work on this product. The
executor is the service account, `shell_exec` runs as that account, and the
documented privileged deployment gives it `sudo`. Anything the host can approve
by itself, the model can approve through `shell_exec`. The approval has to come
from a credential the service account does not hold.

## Decision

Add an opt-in approval mode, `RELAY_SHELL_CONFIRM_APPROVAL=signature`, in which a
confirmation token can be armed only with an SSH signature (SSHSIG, as made by
`ssh-keygen -Y sign`) over a challenge line the server issued with that token.

- **Opt-in, layered on ADR 0009.** Default `client` keeps ADR 0009 behaviour and
  a byte-identical audit record. `signature` requires `confirm_tier3=true` and
  `RELAY_SHELL_CONFIRM_ALLOWED_SIGNERS` (an OpenSSH allowed_signers file);
  either missing refuses startup. Binding, single use, TTL, client binding,
  deny/mode-first ordering and re-classification of the retried call are
  unchanged: the signature replaces only *who may arm*.
- **What the operator signs is what runs.** The plan response carries one ASCII
  line: `relay-shell-confirm v1 {"args":…,"exp":…,"id":…,"op":…,"server":…,"tool":…}`.
  `args` is the redacted audit view (no raw secret reaches the operator's
  terminal or the signed file); `op` is the broker's `sha256(tool \0 op_key)`
  binding over the un-redacted command and every argument; `id` is the token
  fingerprint the audit record uses; `exp` is the wall-clock expiry. The broker
  stores the line with the token and verifies the signature over exactly that
  line (with or without a trailing LF/CRLF, the only encodings a saved file can
  differ by). A signature over one plan cannot arm another.
- **Namespace and keys.** The signature must be in the `relay-shell-confirm`
  namespace, checked by the server as well as by any `namespaces=` option in the
  file, so a git commit or file signature by the same key is refused. Allowed
  signers are read once at startup; unparsable lines, wildcard or negated
  principals, `cert-authority` entries, an empty file and a group/other-writable
  file all refuse startup (asyncssh on its own skips unparsable lines silently).
  `server_info.confirm.signers` lists principals and key fingerprints.
- **Verification is asyncssh's.** `asyncssh.validate_sshsig` (already a runtime
  dependency, ADR 0001) does the cryptography. relay-shell only reads the
  namespace field from the armored header and bounds the input (16 KiB).
- **Audit.** The `operation_confirm` record keeps `token_sha256` and, in signature
  mode only, adds `signature_sha256` and `approver` (the verified principal, empty
  when nothing verified). The tool verifies before the runner, read-only, so the
  record can name the approver; the arm step re-verifies under the broker lock.
  The raw token and the signature body are never logged.
- **Interface.** `operation_confirm` gains an optional `signature` argument. No
  new tool, no new transport, no CLI verb.

## STPA

Purpose: an irreversible operation runs only after a human who holds an approval
key has seen it. Controllers: the MCP client (model), the operator, the broker.
Controlled process: Tier-3 execution through `Relay.run`. Feedback: the plan
response (challenge line), the arm response, the audit records.

- L-1 (from ADR 0009) An irreversible operation runs without the second step its
  issuer was shown. L-2 An irreversible operation runs without the operator having
  approved it, in a deployment that asked for operator approval.
- H-2 A token is armed by a principal other than an allowed operator.
  H-3 An approval for one operation arms a different operation.
  H-4 The operator approves an operation they were shown inaccurately.
- SC-2 Only a valid signature by an allowed key, in the approval namespace, arms a
  token. SC-3 The signature covers the exact challenge issued with that token,
  which binds the operation hash. SC-4 The challenge shows the tool, the redacted
  arguments and the expiry, and is generated by the server, not the client.
- UCA-4 (provided unsafely) `arm` arms a token without a signature. Constraint:
  `arm` returns `False` whenever a verifier is configured. Test:
  `test_broker_arms_only_with_a_signature`.
- UCA-5 (provided unsafely) a signature made for another purpose or another plan
  arms a token. Tests: `test_verifier_refuses_everything_else` (namespace, data,
  key, tamper, oversize) and `test_broker_signature_for_one_plan_does_not_arm_another`.
- UCA-6 (too late) a signature arrives after the token expired. The broker sweeps
  first and re-checks after verification. Test:
  `test_broker_signed_arm_keeps_client_binding_and_expiry`.
- UCA-7 (not provided) the operator cannot approve in time, so the call is not run.
  Resulting state: nothing executed, the plan expires, the client re-plans. That is
  the safe direction for an irreversible operation; raise `CONFIRM_TTL` (up to
  3600 s) for signing workflows.
- CS-4 (H-4, wrong process model) the model shows the operator a misleading
  description and asks for a signature over the real line. Mitigation: the line
  itself names the command and target; the operator must read the line they sign,
  not the model's summary. Residual, documented.
- CS-5 (H-2, conflicting controller) a model with root edits the allowed-signers
  file and restarts the service to load its own key. Not prevented (ADR 0002: the
  service account is the boundary). Made visible: the file is read only at
  startup, a change needs a restart (journal, NRestarts), `server_info` lists
  fingerprints, and AIDE or the deployment's drift check should cover the file.
- CS-6 (stale feedback) a restart drops pending tokens and their challenges; a
  signature for a dropped token verifies against nothing and is refused (fail-safe,
  re-plan).
- Model limits: a signature proves possession of the key, not attention. A
  hardware-backed key (`ed25519-sk`) adds touch, not comprehension.

STRIDE notes: spoofing of the approver is addressed by the off-host key;
tampering with the challenge breaks the signature; repudiation is reduced by the
`approver` field; information disclosure is limited by showing redacted arguments
only; denial of service is bounded by the signature size cap and the existing
pending-token cap.

## Consequences

- One new module (`approval.py`), two settings, one optional tool argument, two
  additive `server_info.confirm` fields (`approval`, `signers`), two additive
  audit argument keys in signature mode.
- Operators need an SSH key outside the relay and a way to move the challenge line
  and the signature between the chat and their terminal. That is deliberate cost
  for rare irreversible work.
- Vertex's ADR-011 plans passkey approval on a server-rendered page. A shared
  approval service could replace this mechanism later; the broker's verifier hook
  is the only integration point.

## Rejected alternatives

- **Host CLI or marker file.** Forgeable by the service account (see Context).
- **HMAC with an operator secret.** The server would need the secret, which puts it
  on the host the model controls.
- **Shelling out to `ssh-keygen -Y verify`.** Works, but adds a subprocess on the
  arm path and a temporary file for the signature; asyncssh already verifies SSHSIG
  in process.
- **Default on.** Violates ADR 0013 (no default-on refusal or confirmation step).
