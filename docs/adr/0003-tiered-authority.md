# ADR 0003: Tiered authority

- Status: Accepted
- Date: 2026-05-19

## Context

With no internal sandbox (ADR 0002), the model sits inside the execution
loop. A bash script cannot assess "this restarts a service users depend on,
ask first"; a reasoning layer can. We want that judgement captured and, when
desired, *enforced* - without crippling the default single-owner workflow.

## Decision

Classify every call into a tier and admit it according to a configured mode.

| Tier | Meaning | Examples |
|------|---------|----------|
| 0 | Read-only / observe | `server_info`, `ssh_hosts`, `ssh_check`, `session_recv` |
| 1 | Reversible / low blast | `ls`, open a PTY, send keystrokes |
| 2 | Stateful / visible impact | service restart, package install, SFTP, forward |
| 3 | Irreversible / high blast | `rm -rf`, `mkfs`, `shutdown`, `drop database`, force-push |

Classification is conservative (ambiguity rounds **up**) and based on the tool
plus a scan of the command/script text.

Modes (`RELAY_SHELL_POLICY_MODE`):

- `open` - permit all, still classify and audit. Default; matches the
  documented single-owner posture.
- `guarded` - refuse Tier >= 2 unless `RELAY_SHELL_POLICY_ALLOW` matches; lower
  tiers pass.
- `readonly` - permit only Tier 0.

`RELAY_SHELL_POLICY_DENY` is evaluated **first in every mode**, including `open`, so
an absolute prohibition always holds. A refusal is audited (with the tier and
reason) and returned as a `[DENIED ...]` string, never an exception.

## Consequences

- The tier is always recorded, so the audit trail shows intent and blast
  radius even when nothing is enforced.
- An operator can tighten a deployment (observation-only client, change
  allowlist) without code changes.
- Classification is heuristic and advisory in `open` mode: defence in depth,
  not a sandbox. It complements, and never replaces, the deployment controls
  in ADR 0002. The regex sets are intentionally simple and auditable; extend
  them per deployment via the deny/allow lists rather than by widening the
  built-in heuristics silently.

## Rejected

- No classification (rely only on deployment controls): loses the intent
  record and the ability to tighten without a rebuild.
- A full capability/command allowlist as the primary control: unbounded for
  general administration; high friction for low risk reduction on a
  single-owner host. The deny list plus `guarded` allow list covers the cases
  that matter without that cost.
