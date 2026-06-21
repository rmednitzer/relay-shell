---
title: Home
---

# relay-shell documentation

A governed [Model Context Protocol](https://modelcontextprotocol.io) server for
**complete shell and SSH operation** — with an append-only, output-hashed audit
trail, a tiered-authority policy layer, secret redaction, and strict resource
and timeout bounds.

This site is generated from the
[`docs/`](https://github.com/rmednitzer/relay-shell/tree/main/docs) folder. For
the project overview and install steps see the
[README](https://github.com/rmednitzer/relay-shell#readme); for the threat model
and supported versions see
[`SECURITY.md`](https://github.com/rmednitzer/relay-shell/blob/main/SECURITY.md).

## Guides

- [Architecture](architecture.md) — the request lifecycle, the module map, and the trust boundary.
- [Tool reference](tools.md) — every MCP tool, resource, and prompt, with tiers and tests.
- [Deployment](deployment.md) — service account, network edge (Caddy + ACME), OAuth, and audit shipping.
- [Authentication](auth.md) — the OAuth 2.1 lifecycle and the opt-in-by-default posture.
- [Audit shipping](audit-shipper.md) — Vector, Fluent Bit, and `systemd-journal-remote` recipes.
- [Maintenance runbook](runbook.md) — the audit / review / validate / enhance / extend procedures and the backlog.

## Architecture Decision Records

The [ADR index](adr/README.md) records every decision with its status and date —
the no-sandbox full-access posture (0002), tiered authority (0003), edge-TLS
automation (0004), the seccomp-notify audit channel (0006), and the audit hash
chain (0007).

---

*Source: [github.com/rmednitzer/relay-shell](https://github.com/rmednitzer/relay-shell) · Apache-2.0 licensed.*
