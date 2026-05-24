# Architecture Decision Records

The decisions documented here shape the trust boundary, the runtime,
and the operator-facing posture of `relay-shell`. Read them in order
the first time; revisit one when its subject area changes.

The format follows [Michael Nygard's ADR
template](https://github.com/joelparkerhenderson/architecture-decision-record/blob/main/locales/en/templates/decision-record-template-by-michael-nygard/decision-record-template-by-michael-nygard.md):
context, decision, consequences. Each ADR has a `Status` line at the
top. Status values:

| Status      | Meaning                                                  |
|-------------|----------------------------------------------------------|
| Proposed    | Drafted, not yet adopted.                                |
| Accepted    | Adopted; the codebase reflects the decision.             |
| Superseded  | Replaced by a later ADR; see `Superseded by` line.       |
| Deprecated  | No longer applicable; kept for history.                  |

## Index

| ADR | Title | Status | Date | Subject |
|-----|-------|--------|------|---------|
| [0001](0001-runtime-and-sdk.md) | Runtime, SDK, and SSH library | Accepted | 2026-05-19 | Why Python 3.12 + the official `mcp` SDK + `asyncssh`, with the alternatives that were rejected (`paramiko`, building a transport from scratch). |
| [0002](0002-no-sandbox-full-access.md) | Unsandboxed, full-access posture | Accepted | 2026-05-19 | Why the executor runs without a meaningful internal sandbox - the project exists to give an MCP client real administrative power, so the safety story is compensating controls (audit, tier policy, redaction, bounds, deployment discipline) instead. |
| [0003](0003-tiered-authority.md) | Tiered authority | Accepted | 2026-05-19 | The four-tier classification (read-only / reversible / stateful / irreversible) plus `open` / `guarded` / `readonly` admission modes that consume it. The deny list is enforced first in every mode. |
| [0004](0004-edge-tls-automation.md) | Automated TLS at the edge | Accepted | 2026-05-20 | Why `deploy/install-edge.sh` provisions Caddy + ACME (Let's Encrypt) for the HTTP transport, and why certbot+cron and native TLS in the Python service were rejected. |
| [0005](0005-codebase-validation.md) | Codebase validation against known-good sources | Accepted | 2026-05-24 | A repeatable validation pass against the upstream `mcp` / `asyncssh` / OAuth surfaces, the audit record schema, and the documented redaction / tier behavior. Captures the 2026-05-24 pass outcome and the three small documentation-drift findings it resolved. |

## When to write an ADR

Any of the following needs an ADR before code lands:

- A new transport (e.g. unix-socket alongside `stdio` / `streamable-http`).
- A new auth provider (e.g. JWT static-keys alongside the file-backed OAuth 2.1).
- A change to the audit-record shape or to the no-sandbox posture.
- A new policy category (not just another verb in the existing
  `TIER2_PATTERN` / `TIER3_PATTERN`; see `docs/runbook.md` §6.4).

Routine additions - a new tool, a new redaction pattern, a tightened
test - do not need an ADR; they go through the normal review loop. The
runbook §6 has recipes per case.

## How to write one

1. Number sequentially. Next free number is **0006**.
2. Filename pattern: `NNNN-short-slug.md`.
3. Required header:

   ```
   # ADR NNNN: <Title>

   - Status: Accepted
   - Date: YYYY-MM-DD
   ```

4. Sections: `Context`, `Decision`, `Consequences`, `Rejected
   alternatives` (when applicable).
5. Reference the ADR by number in code or other docs, not by file
   path - the path is stable but the number is the canonical handle.

## Cross-references

- `docs/architecture.md` - request lifecycle, module table, and how
  the ADRs map onto the runtime.
- `docs/runbook.md` §6 - extension recipes that may require an ADR
  before code lands.
- `SECURITY.md` - the threat model and how ADRs 0002 / 0003 constrain it.
