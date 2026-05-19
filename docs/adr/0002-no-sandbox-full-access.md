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
