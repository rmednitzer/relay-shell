# Backlog — 2026-06-12 audit pass deferrals

This file is the deferral register for the 2026-06-12 full audit pass. Each
item is a finding from `audit/02-security-findings.md` that was **not** fixed
in the pass, with the schema the audit charter requires.

The project's **canonical, living backlog** is [`docs/runbook.md`](docs/runbook.md)
§7 (and the §8 per-file docs plan). This file does not replace it; it records
the audit-pass-specific deferrals and points into §7 where an item belongs in
the ongoing queue. When an item here is actioned, close it in the same place
its kind is tracked (runbook §7 for capability/quality/ops/security-hardening,
§8 for docs).

Severity order within each section: low before info; smaller effort first.

## Closed (follow-up work after the audit pass)

Resolved in the backlog-work PR that followed the 2026-06-12 audit pass.
Do not re-add.

| ID | Title | Resolution |
|---|---|---|
| SEC-1 | `ssh_keyscan` target hosts bypass `RELAY_SHELL_POLICY_DENY` | **Closed.** Added `_policy_text_ssh_keyscan(hosts)` and wired it into the wrapper so the deny list gates scan targets; the call is audited `denied=True` on a match. The tier-over-classification tradeoff was accepted (only bites `guarded` mode; `open` is advisory, `readonly` already refuses Tier 1; `POLICY_ALLOW` is the escape hatch; consistent with the transfer tools) and is documented in the builder docstring. Tests: deny-gates-host, non-denied-host-runs, classifier-tradeoff pin, and the R-002 builder-contract line. |
| QUAL-1 | A few `seccomp` termination tests assert via "does not hang" | **Closed.** Added explicit observable asserts to the five control-flow tests (`m._count == 0` after a drain break, `== 1` after isolated dispatch, `is None` for the suppressed-ioctl `_respond_continue`). Test-only. |
| TOOL-1 | gitleaks flags synthetic redaction fixtures as secrets | **Closed.** Added a tightly-scoped `.gitleaks.toml` (extends the default ruleset) allowlisting only `tests/*.py`, `docs/runbook.md`, and `audit/*.md`. Validated: history scan drops from 13 leaks to 0, while a canary key planted under `src/` is still caught. Wiring a CI secret-scan job remains separate. |

## Security

| ID | Finding | Severity | Effort | Rationale | Suggested approach | Dependencies | Owner role |
|---|---|---|---|---|---|---|---|
| SEC-2 | [S-003] `dependency-review.yml` re-enables `persist-credentials` | low | S | `actions/checkout@v6` defaults it off; the workflow restores it so the action can `git fetch` base/head refs. The token lands in `.git/config` for the job. Very low risk (only the pinned action runs, read-only token). | Try the action's explicit `base-ref`/`head-ref` inputs to drop the credential helper; if that fails, keep the documented justification. | None | maintainer / CI |

## Reliability

| ID | Finding | Severity | Effort | Rationale | Suggested approach | Dependencies | Owner role |
|---|---|---|---|---|---|---|---|
| REL-1 | [Q-003] Starlette `TestClient` deprecation in `tests/test_metrics.py:15` | low | M | `pytest` emits one `StarletteDeprecationWarning` ("install httpx2"). Upstream deprecation; the test passes. Becomes a hard break only when the pinned Starlette removes the shim. | Track the Starlette/httpx2 migration; bump and migrate the test client when the pin advances. No action until then. | upstream Starlette/httpx | maintainer |

## Quality

(Empty — QUAL-1 closed in the follow-up work above.)

## Documentation

(Closed in this pass — D-001/D-002/D-003 are reconciled. No open docs
deferrals. The frozen ADR 0008 incidental `mcp==1.27.1` mention is
deliberately left as-authored per the project's no-retro-edit-of-decision-
records convention; see `audit/03-final-report.md`.)

## Tooling

| ID | Finding | Severity | Effort | Rationale | Suggested approach | Dependencies | Owner role |
|---|---|---|---|---|---|---|---|
| TOOL-2 | [Q-001] ruff pinned at 0.15.16 in `requirements.txt` + `.pre-commit-config.yaml`, but the `dev` floor resolves 0.15.17 | low | S | CI installs the unpinned `dev` extra and runs whatever ruff is latest, which can drift from the pinned pre-commit/requirements. No behavioral diff today; Renovate self-corrects over time. | Optionally pin the CI ruff to the pre-commit `rev` for reproducibility, or accept Renovate's cadence. | Renovate cadence | maintainer / CI |
| TOOL-3 | A CI secret-scan job (gitleaks) | info | S | `.gitleaks.toml` now exists (TOOL-1), so a CI job would run clean on the current tree. Optional defense-in-depth; not wired yet to avoid adding a required check without a decision. | Add a `gitleaks` workflow using `-c .gitleaks.toml`, pinned by SHA with least-privilege `permissions`. | TOOL-1 (done) | maintainer / CI |

## Carried forward from prior engagement packs (operator action)

| ID | Item | Severity | Effort | Rationale | Owner role |
|---|---|---|---|---|---|
| F-G2 | Branch protection on `main` — **now enabled** (status changed since the prior packs) | resolved (headline) | — | Prior packs (`audit/2026-06-01-engagement.md` §7.1) carried this as an open HIGH item ("`main` accepts direct pushes"). **Verified this session** via the GitHub branches API: `main` reports `"protected": true` [V], so the core of F-G2 is closed. The *granular* rules (required reviews, required signed commits, linear history) were not separately enumerable through the available MCP tool surface, so those specifics are `[UNVERIFIED]`; confirm them in Settings → Branches if signed-commit enforcement (prior pack P2-3) is wanted. | repo owner |

## Notes on items NOT added here

- No critical / high / medium **code** security findings were produced by
  this pass, so there is no remediation backlog of that kind.
- The structural refactor candidates (`R-001` table-driven tool registration,
  `R-004` OAuth store `Protocol`) already live in runbook §5.2 and are not
  duplicated here.
- No destructive or irreversible operation was proposed by this pass
  (no history rewrite, no dependency major bump, no schema change), so the
  charter's "proposals, not executed" bucket is empty.
