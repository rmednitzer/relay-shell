# ADR 0002: Unsandboxed, full-access posture

- Status: Accepted
- Date: 2026-05-19

## Context

`relay-shell` exists to give an MCP client genuine shell and SSH mastery over hosts
the operator administers. A meaningful internal sandbox (filesystem
confinement, dropped capabilities, a syscall allowlist, no-new-privileges)
directly contradicts that purpose: the tool's job is to run arbitrary
commands, escalate where the operator legitimately can, and reach other
hosts. Half-sandboxing produces a tool that is both less capable *and* not
actually safe, while implying a containment guarantee it does not provide.

## Decision

Run unsandboxed, with the privileges of the service account, by design. Do
not apply `ProtectSystem=strict`, `NoNewPrivileges`, `ProtectHome`, or a
restrictive `SystemCallFilter` to the service. Treat the **service account
and its credentials** - not an in-process sandbox - as the security boundary.

## Compensating controls (mandatory, not optional)

- Append-only, output-hashed audit of every call (body never logged).
- Tiered-authority classification with selectable admission modes
  (`open`/`guarded`/`readonly`) and an always-on deny list (ADR 0003).
- Secret redaction of audited arguments.
- Strict timeout/output/session bounds; structured, non-propagating errors.
- Optional OAuth 2.1 edge and a TLS + IP-allowlisted reverse proxy.
- Deployment discipline: dedicated unprivileged account, scoped SSH keys,
  resource caps, off-host audit shipping (see `docs/deployment.md`).

## Full-root execution contract (2026-10-06 clarification)

For a host-administrator deployment, the account must have operator-authorized
noninteractive sudo for arbitrary commands. UID 0 alone is not sufficient:
execution must retain the host's capability bounding set and user/mount namespace.
The shipped service envelope explicitly avoids settings that clip those rights.
`ProtectKernelModules`, `ProtectKernelLogs` and `ProtectClock` are not harmless
hardening for this role; they remove capabilities and/or filter system calls.
`PrivateTmp` is also incompatible with an unmodified host filesystem view.

Keep the daemon's dedicated identity and elevate individual commands through
sudo. Resource limits, restrictive creation umask, network authentication, audit
logging and the tool's admission/confirmation policy remain in force. This does
not authorize changing unrelated application identities or disabling the tool's
own safeguards. A deployment without root authority must be described as such,
not reported as a full-root administrator because an `id` probe happens to pass.

After restart, run a read-only root probe through an actual relay tool call.
Check real/effective UID and GID, `NoNewPrivs`, `CapEff`, `CapBnd`, and the user
and mount namespace links against PID 1. Do not change clocks, load modules or
remount filesystems just to test privileges. A successful host-shell probe
outside the service does not substitute for an execution-path test.

## Consequences

- The tool is fully capable and honest about its posture.
- If the MCP client or transport is compromised, the attacker gains the
  service account's reach. This residual risk is stated plainly in
  `SECURITY.md` so it is designed around (scoping, isolation) rather than
  discovered. Re-evaluate if the host gains multi-tenant use or sensitive
  data, or if credential scoping per role is introduced.

## Rejected

- Full sandbox: breaks the capability; defeats the purpose.
- Partial sandbox presented as containment: misleading and still bypassable
  for the operations the tool must perform.
