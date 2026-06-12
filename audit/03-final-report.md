# Phase 8: Final report — 2026-06-12 full audit pass

Audit / validation / hardening / documentation pass over `rmednitzer/relay-shell`
at `origin/main` HEAD `6bb3518` (#87). Branch: `claude/bold-bell-9h5luz`
(the session harness pins development here; the charter's
`audit/2026-06-12-full-pass` name is recorded in `audit/00-inventory.md`).

## Executive summary

`relay-shell` is in strong shape. It is a mature MCP shell/SSH server with a
deliberate unsandboxed posture (ADR 0002) wrapped in audit, tiered policy,
redaction, and resource bounds — and that trust boundary holds up under
scrutiny. Two prior assurance engagements (2026-05-27, 2026-06-01) did
thorough work, and it shows.

This pass found **no critical, high, or medium security findings**. Every
automated scanner came back clean. The one concrete, actionable item was
**documentation drift**: the `mcp` SDK pin moved 1.27.1 → 1.27.2 in PR #66
(2026-06-04) without the runbook §8.9 follow-through, so the README,
`docs/architecture.md`, and the ADR record still named 1.27.1. That is now
reconciled. The remaining findings are low/informational hardening and
tooling notes, deferred to `BACKLOG.md` with rationale.

No executor, policy, redaction, or audit-record behavior was changed in this
pass, so the regression bar is unmoved by construction; the changes are
documentation and audit evidence only (verified: the PR diff touches no
`src/` or `tests/` file).

A carried-forward HIGH governance item from the prior packs (F-G2, branch
protection on `main`) was **verified resolved** this session: the GitHub
branches API reports `main` as `protected: true`, contradicting the prior
`[S]`-tagged assumption that it accepted direct pushes.

## Baseline vs post-fix metrics

Because no code changed, the quality gates are identical before and after.
"Post-fix" here means "after the documentation reconciliation."

| Metric | Baseline (HEAD 6bb3518) | Post-pass | Source |
|---|---|---|---|
| ruff check | clean | clean | `.venv/bin/ruff check .` |
| ruff format --check | clean (46 files) | clean | `.venv/bin/ruff format --check .` |
| mypy --strict | 0 errors, 19 files | 0 errors | `.venv/bin/mypy` |
| pytest (default) | 339 passed, 13 deselected | 339 passed, 13 deselected | `.venv/bin/pytest` |
| pytest -m fuzz | 13 passed | 13 passed | `.venv/bin/pytest -m fuzz` |
| coverage (subprocess) | 93% (floor 90) | 93% | `coverage run -m pytest && coverage report` |
| semgrep (`p/python`) | 0 findings / 19 files | 0 | `uvx semgrep scan --config p/python` |
| bandit (medium+) | 0 findings | 0 | `uvx bandit -r src -ll` |
| pip-audit (`requirements.txt`) | 0 vulns | 0 | `uvx pip-audit -r requirements.txt --strict` |
| trivy (vuln/misconfig/secret) | 0 / 0 / 0 | 0 | `trivy fs --scanners vuln,misconfig,secret` |
| gitleaks | fixtures + `.venv` only | unchanged | `gitleaks detect` |

Vulnerability counts by severity (dependency + SAST): **critical 0, high 0,
medium 0, low 0** across pip-audit, trivy, semgrep, bandit. Lint/type
violations: **0**.

## Commits in this pass (one-line rationale)

| Commit | Rationale |
|---|---|
| `8125772` | Phase 0 inventory: component map, deps, CI, environment toolchain, git state |
| `9bd2333` | Phase 1 baseline + Phase 2/3 findings register (scanners clean; runbook §2 behavioral checks pass) |
| `6f48f18` | Phase 5: sync `mcp`/`asyncssh` version strings in README + architecture.md to the pinned set (D-001/D-003) |
| `d9b8fcd` | Phase 6: ADR follow-through for the `mcp` bump — ADR 0001 Consequences line, ADR 0005 2026-06-12 outcome, ADR index subject |
| `306b067` | Phase 5: CHANGELOG `[Unreleased]` note for the pin-drift reconciliation |
| `edd2801` | Phase 7: `BACKLOG.md` deferral register (cross-references runbook §7) |
| `2801c82` | F-G2 verified resolved — `main` reports `protected: true` via the API |

(Plus this report under `audit/03-final-report.md` in the PR-finalizing commit.)

## Residual risk statement

- The **documented unsandboxed full-access posture** (ADR 0002) is unchanged
  and remains the project's defining risk: a compromised MCP client or
  transport obtains the service account's capabilities on this host and any
  host its SSH credentials reach. This is by design and is stated plainly in
  `SECURITY.md`; it is out of scope to "fix."
- **S-001** (`ssh_keyscan` target hosts bypass the deny list) is a low-impact
  consistency gap left open with a deliberate tradeoff (feeding hosts to the
  policy text also feeds the tier classifier); deferred to `BACKLOG.md`
  `SEC-1` as a decision, not silently changed.
- **Granular branch-protection rules** on `main` (required reviews / signed
  commits / linear history) were not enumerable through the available tool
  surface; only the headline `protected: true` is `[V]`. If signed-commit
  enforcement is wanted, confirm it in Settings → Branches (`BACKLOG.md`
  F-G2 note).
- The CI **Python 3.14** matrix leg was not reproducible locally (no 3.14
  interpreter in this environment); it remains covered by CI per `ci.yml`
  and is marked `[UNVERIFIED]` for this session only.
- Frozen records were left intact on purpose: ADR 0008's incidental
  `mcp==1.27.1` mention (written 2026-06-08, after the bump) is a factual
  off-by-one in a decision record, but the project's convention is not to
  retro-edit decision records, so it is documented here rather than rewritten.

## Top 5 backlog items

Ordered by priority. Full schema in `BACKLOG.md`.

1. **F-G2 (governance)** — confirm the *granular* `main` protection rules
   (required reviews, required signed commits). Headline protection is on;
   the specifics are unconfirmed. ~5 min, owner: repo owner.
2. **SEC-1 (security, S)** — decide and (if accepted) implement feeding
   `ssh_keyscan` hosts to `policy_text` so the deny list gates scan targets,
   weighing the tier-over-classification tradeoff. Needs paired tests.
3. **SEC-2 (security/CI, S)** — drop `persist-credentials: true` from
   `dependency-review.yml` by passing explicit base/head refs, or keep the
   documented justification.
4. **TOOL-2 / Q-001 (tooling, S)** — pin CI ruff to the pre-commit `rev` so
   the unpinned `dev`-extra resolve cannot drift from the pinned local hooks.
5. **REL-1 / Q-003 (reliability, M)** — track the Starlette `TestClient` →
   httpx2 migration; act when the pinned Starlette removes the shim.

## Methodology note

Every metric and finding in this pack is backed by a command run in this
session (cited in `audit/01-baseline.md` and `audit/02-security-findings.md`).
Unverifiable items are tagged `[UNVERIFIED]`. No destructive or irreversible
operation was performed; no dependency was bumped; no history was rewritten;
no schema changed. Audit evidence collection (Phases 0-3) and the
documentation remediation (Phases 5-7) were kept in separate commits per the
charter.
