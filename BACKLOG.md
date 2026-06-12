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

## Security

| ID | Finding | Severity | Effort | Rationale | Suggested approach | Dependencies | Owner role |
|---|---|---|---|---|---|---|---|
| SEC-1 | [S-001] `ssh_keyscan` target hosts bypass `RELAY_SHELL_POLICY_DENY` (`server.py:1127`, `policy_text=""`) | info/low | S | The transfer tools (`ssh_upload`/`download`/`forward`) encode the host in synthetic policy text so the deny list gates their targets; `ssh_keyscan` does not. Low impact (Tier 1, regex-validated hosts, key-fetch only), but inconsistent. | Add `_policy_text_ssh_keyscan(hosts)` mirroring the transfer builders. **Decide the tradeoff first** (needs an ADR-lite note): the same text feeds the tier classifier, so an adversarial hostname containing a `\b`-bounded heuristic word (e.g. `sudo.example.com`) would over-classify the scan to Tier 2 and refuse it in `guarded`. A synthetic-prefix form does not avoid this. Pair the change with positive + near-miss tests. | None | maintainer / security |
| SEC-2 | [S-003] `dependency-review.yml` re-enables `persist-credentials` | low | S | `actions/checkout@v6` defaults it off; the workflow restores it so the action can `git fetch` base/head refs. The token lands in `.git/config` for the job. Very low risk (only the pinned action runs, read-only token). | Try the action's explicit `base-ref`/`head-ref` inputs to drop the credential helper; if that fails, keep the documented justification. | None | maintainer / CI |

## Reliability

| ID | Finding | Severity | Effort | Rationale | Suggested approach | Dependencies | Owner role |
|---|---|---|---|---|---|---|---|
| REL-1 | [Q-003] Starlette `TestClient` deprecation in `tests/test_metrics.py:15` | low | M | `pytest` emits one `StarletteDeprecationWarning` ("install httpx2"). Upstream deprecation; the test passes. Becomes a hard break only when the pinned Starlette removes the shim. | Track the Starlette/httpx2 migration; bump and migrate the test client when the pin advances. No action until then. | upstream Starlette/httpx | maintainer |

## Quality

| ID | Finding | Severity | Effort | Rationale | Suggested approach | Dependencies | Owner role |
|---|---|---|---|---|---|---|---|
| QUAL-1 | [Q-004] A few `seccomp` termination tests assert via "does not hang" | info | S | `test_drain_breaks_*`, `test_respond_continue_swallows_ioctl_error`, `test_dispatch_callback_exception_is_isolated` verify control-flow termination/exception isolation with no explicit `assert`. Legitimate (a regression hangs and times out) but easy to mistake for a stub. | Where cheap, add a trailing `assert` on an observable (e.g. the dispatch counter, or a flag set by the callback) so intent is explicit. | None | maintainer |

## Documentation

(Closed in this pass — D-001/D-002/D-003 are reconciled. No open docs
deferrals. The frozen ADR 0008 incidental `mcp==1.27.1` mention is
deliberately left as-authored per the project's no-retro-edit-of-decision-
records convention; see `audit/03-final-report.md`.)

## Tooling

| ID | Finding | Severity | Effort | Rationale | Suggested approach | Dependencies | Owner role |
|---|---|---|---|---|---|---|---|
| TOOL-1 | [S-004] gitleaks flags synthetic redaction fixtures as secrets | info | S | Every gitleaks hit is a deliberately fake fixture in `tests/` or `docs/runbook.md` (or vendored `.venv`). No real credential. If a CI secret-scan is ever added it will be noisy. | Add a `.gitleaks.toml` allowlist for `tests/` + `docs/runbook.md` before wiring any CI secret-scan job. | TOOL-? (a CI secret-scan job, if pursued) | maintainer / CI |
| TOOL-2 | [Q-001] ruff pinned at 0.15.16 in `requirements.txt` + `.pre-commit-config.yaml`, but the `dev` floor resolves 0.15.17 | low | S | CI installs the unpinned `dev` extra and runs whatever ruff is latest, which can drift from the pinned pre-commit/requirements. No behavioral diff today; Renovate self-corrects over time. | Optionally pin the CI ruff to the pre-commit `rev` for reproducibility, or accept Renovate's cadence. | Renovate cadence | maintainer / CI |

## Carried forward from prior engagement packs (operator action)

| ID | Item | Severity | Effort | Rationale | Owner role |
|---|---|---|---|---|---|
| F-G2 | Branch protection on `main` not enabled (carried from `audit/2026-06-01-engagement.md` §7.1, originally 2026-05-27) | high (governance) | S | Until it lands, CODEOWNERS is advisory, `main` accepts direct pushes, and signed-commits cannot be enforced. A ~5 min GitHub Settings → Branches action. **Not re-verified via API this session** — reasserted until closed. `[UNVERIFIED]` this pass. | repo owner |

## Notes on items NOT added here

- No critical / high / medium **code** security findings were produced by
  this pass, so there is no remediation backlog of that kind.
- The structural refactor candidates (`R-001` table-driven tool registration,
  `R-004` OAuth store `Protocol`) already live in runbook §5.2 and are not
  duplicated here.
- No destructive or irreversible operation was proposed by this pass
  (no history rewrite, no dependency major bump, no schema change), so the
  charter's "proposals, not executed" bucket is empty.
