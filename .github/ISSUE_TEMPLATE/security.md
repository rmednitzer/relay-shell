---
name: Security report
about: Report a vulnerability or a violation of a security guarantee.
title: "[security] "
labels: ["security"]
---

<!--
STOP. Please do not paste working exploit payloads into a public issue.

Preferred reporting channels (in order):

1. Open a private security advisory on the repository:
   https://github.com/rmednitzer/relay-shell/security/advisories/new
2. Or open an issue without exploit detail and request a private channel
   to follow up.

This template exists so that something *can* be filed publicly when the
finding is generic (e.g. "the redaction pattern misses a known token
shape") and exploitability is low. Use the private path for anything
sensitive. See SECURITY.md.

Indicative response target: 7 days to triage.
-->

## In scope?

The following are explicitly in scope (per `SECURITY.md`):

- [ ] Audit-trail evasion (output body leaking into the audit log, hash
      / length missing, append-only bypass).
- [ ] Policy / tier bypass (denylist bypass; `readonly` or `guarded`
      admitting commands they should refuse).
- [ ] Secret leakage into logs (a real secret shape that redaction
      misses).
- [ ] Auth or transport handling (OAuth provider, TLS edge, CIDR
      allowlist).
- [ ] Sandbox-escape-equivalent privilege gain *beyond* the documented
      service-account posture.

Out of scope: the documented unsandboxed full-access posture itself,
and the ability of a correctly authenticated, policy-permitted caller
to run commands.

## Summary

<!-- One or two sentences. What is the issue and which guarantee does
it violate? Reference the section of `SECURITY.md` or the ADR it
contradicts. -->

## Impact

<!-- Which posture is affected (scoped / privileged), which mode (open
/ guarded / readonly), and what the attacker gains. Be specific about
prerequisites (already-authenticated MCP client? Compromised SSH host?
Local user on the relay host?). -->

## Reproduction sketch

<!-- Enough to confirm the issue. Do NOT include working exploit code
in a public issue. A sentence and a pointer to the affected file is
fine; use the private advisory channel for full detail. -->

## Suggested mitigation (optional)

<!-- Where in the source the fix likely belongs. Helpful but not
required. -->

## Disclosure preference

- [ ] Standard disclosure (public issue + fix in a regular release).
- [ ] Coordinated disclosure (private advisory until fix ships; credit
      requested as `<your handle>`).
