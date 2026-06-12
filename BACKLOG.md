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

Resolved in the backlog-work PRs that followed the 2026-06-12 audit pass.
Do not re-add.

| ID | Title | Resolution |
|---|---|---|
| SEC-1 | `ssh_keyscan` target hosts bypass `RELAY_SHELL_POLICY_DENY` | **Closed** (PR #89). Added `_policy_text_ssh_keyscan(hosts)` and wired it into the wrapper so the deny list gates scan targets; the call is audited `denied=True` on a match. The tier-over-classification tradeoff was accepted (only bites `guarded` mode; `open` is advisory, `readonly` already refuses Tier 1; `POLICY_ALLOW` is the escape hatch; consistent with the transfer tools) and is documented in the builder docstring. Tests: deny-gates-host, non-denied-host-runs, classifier-tradeoff pin, and the R-002 builder-contract line. |
| QUAL-1 | A few `seccomp` termination tests assert via "does not hang" | **Closed** (PR #89). Added explicit observable asserts to the five control-flow tests (`m._count == 0` after a drain break, `== 1` after isolated dispatch, `is None` for the suppressed-ioctl `_respond_continue`). Test-only. |
| TOOL-1 | gitleaks flags synthetic redaction fixtures as secrets | **Closed** (PR #89). Added a tightly-scoped `.gitleaks.toml` (extends the default ruleset) allowlisting only `tests/*.py`, `docs/runbook.md`, and `audit/*.md`. Validated: history scan drops from 13 leaks to 0, while a canary key planted under `src/` is still caught. The CI job that consumes it landed as TOOL-3. |
| TOOL-3 | A CI secret-scan job (gitleaks) | **Closed** (PR #90). Added `.github/workflows/gitleaks.yml` (push to main, PRs, daily, `workflow_dispatch`). Self-contained, supply-chain careful: pinned gitleaks 8.30.1 installed by discovering the exact asset name from the release's own checksums file and verifying the tarball before extracting (no hardcoded checksum, no third-party action / license endpoint); `permissions: contents: read`; `gitleaks detect -c .gitleaks.toml` fails the job on any finding. Validated: YAML parses, the detect command runs clean on the tree, the install asset-discovery + checksum-verify pipeline was dry-run (match OK, tamper FAILS), and both first live runs (PR #90 and the post-merge push to `main`) concluded `success`. Making it a *required* check is a repo-owner branch-protection decision. |
| SEC-2 | `dependency-review.yml` re-enables `persist-credentials` | **Closed** (PR #91). Removed the checkout step from the job entirely. Source-verified at the pinned action SHA (`a1d282b`, v5.0.0): for `pull_request` events the action takes base/head SHAs from the event payload (`src/git-refs.ts`) and calls the Dependency Graph compare API (`src/main.ts`); it spawns no git process and never reads the working tree unless a local `config-file` input is used (none is). The recorded "shells out to `git fetch`" rationale does not match this version's source. No checkout means no persisted token and no repo bytes on disk. Self-validated: the change runs on its own PR's `dependency-review` check. |
| REL-1 | Starlette `TestClient` deprecation in `tests/test_metrics.py` | **Closed** (PR #92). The "install httpx2" warning came from `starlette.testclient`, not from needing httpx 2 — re-checked this session: driving `/metrics` through httpx's own `ASGITransport` (already pinned, httpx 0.28.1) returns the identical response with **zero** warnings, and the `/metrics` custom route needs no lifespan context. Migrated the four HTTP `/metrics` tests off `starlette.testclient.TestClient` to a small `_http_get` ASGITransport helper. Suite now reports 0 warnings (was 1); `pytest -W error::DeprecationWarning tests/test_metrics.py` passes. No httpx2 bump, no dependency change. The earlier "blocked on upstream" disposition was wrong. |
| TOOL-2 | ruff pin skew across `requirements.txt` / `.pre-commit-config.yaml` / the `dev` extra resolve | **Closed (accepted as designed, evidence-verified).** `renovate.json5` enables the `pre-commit` manager and groups `pip_requirements` updates on the weekly schedule, and the history shows it updating both pinned locations in practice (#83 pre-commit ruff `v0.15.16`, #84 python dependencies, #85 pre-commit `v6`). The skew window is therefore bounded by the weekly Renovate cadence, both versions lint the tree identically, and a manual pin would only fight the bot. No change needed; re-open only if a ruff release ever splits lint behavior inside one cadence window. |

## Security

(Empty — SEC-1 and SEC-2 closed in the follow-up work above.)

## Reliability

(Empty — REL-1 closed in the follow-up work above.)

## Quality

(Empty — QUAL-1 closed in the follow-up work above.)

## Documentation

(Closed in this pass — D-001/D-002/D-003 are reconciled. No open docs
deferrals. The frozen ADR 0008 incidental `mcp==1.27.1` mention is
deliberately left as-authored per the project's no-retro-edit-of-decision-
records convention; see `audit/03-final-report.md`.)

## Tooling

(Empty — TOOL-1/TOOL-3 closed by the follow-up work and TOOL-2 closed as
accepted-as-designed with Renovate evidence; see the Closed table above.)

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
