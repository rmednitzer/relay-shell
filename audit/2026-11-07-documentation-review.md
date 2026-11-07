# Documentation and Pages review — 2026-11-07

## Scope and baseline

Public repository baseline: `e7f4256b63477fd2da6bcad8d2437d07cc2c17f5`
(main), latest release v0.5.2. The inventory contained 54 tracked Markdown
documents, including contributor/templates, eight site guides, 15 ADR/index
files, deployment/dependency/fixture READMEs and frozen audit packs.
[PR #281](https://github.com/rmednitzer/relay-shell/pull/281) carries the corrections.

Antigravity was invoked through Vertex for a read-only repository and published
Pages review. Its completed report supplied a coverage manifest and actionable
findings. Independent review compared proposed corrections with actual source,
workflow steps, lock headers and external repository settings. The provider's
counts, line references and historical descriptions are not authoritative.
In particular, its claimed missing latest SDK/SSH pin entry in ADR 0001 was
rejected: the current Consequences section already contains that entry.

## Verified findings and disposition

| Area | Correction |
| --- | --- |
| Quickstart and agent setup | Use the qualified hashed development profile, then no-dependency editable installation. |
| Deployment | Replace the superseded manual install with the locked installer's stopped-service procedure and link bounded failure/interruption recovery. |
| Edge installer | Exported EDGE variables take precedence over the operator file, including explicit empty values; document sudo environment selection. |
| Audit and resource limits | State crash/degraded-sink limits, audit-before-notice order, character input limits, SFTP/session/remote-timeout exceptions and resource/prompt truncation. |
| OAuth | Reauthorization also follows grant revocation, reuse detection, resource changes or applicable recovery/migration. |
| Release/SBOM runbook | Current tags use complete profiles, independent workflow tooling locks and separate runtime/builder/tool environments; preserve historical fallback limits. |
| Contributor checklists | Include scope inputs and all affected profile/tooling lock regeneration commands. |
| Release trust | Append dated v0.5.0–v0.5.2 signature, tag-object and main-ancestry evidence; recheck external controls. |
| Current terminology | Correct MCPServer references, the CLI flag comment, optional HTTP-extra comment and broker operation-key docstring. Executable behavior is unchanged. |
| Historical runner record | Append a dated current-runner clarification to BACKLOG; preserve the initial qualification and historical ADRs/audit packs. |
| Vector example | Replace retired repository instructions; declare the metrics source, remove zero-age filtering, use valid compression/routing/buffer settings and handle non-object JSON. Document receiver protocol and rotation/backfill limits. |
| Pages assets | Use system fonts, removing Google font requests. |

## Validation evidence

- Baseline live crawl: all 23 sitemap URLs returned HTTP 200.
- All 22 registered tools are represented in README and the tool reference.
- Strict MkDocs builds and documentation-environment `pip check` passed.
- Relative file-link checks covered the 54 baseline Markdown documents; generated
  file/anchor checks covered all 24 HTML files, including the 404 page.
- Generated pages contain no Google Fonts requests.
- Vector 0.61.0's original example failed configuration loading on boolean
  compression. The corrected example passed `vector validate --no-environment`.
  Synthetic VRL cases passed for an object, malformed JSON, a scalar and an array;
  original message/file fields were retained and invalid records gained parse errors.
  The official Linux release archive was checked against the GitHub-reported SHA-256
  `84a27c3ad6b772fdb05bb76ea01a31498bfc8f5e71f32cc78a0d96841f1aa827`
  and its validator ran in a disposable task directory under an unprivileged identity.
- `pyproject.toml` and pre-commit parsed configuration remain identical to baseline.
  The broker's executable AST remains identical after removing the module docstring.
- SSH signatures and main ancestry were checked for all seven release tags.
  Ruleset and immutable-release observations are recorded in
  [release trust](../docs/release-trust.md#verification-update-2026-11-07).
  The GitHub `pypi` environment had a required-reviewer rule on this date;
  PyPI account-side trusted-publisher configuration was not independently inspected.

The final revision's required CI and Pages deployment receipts belong to PR #281
and its linked main workflow runs. A submitted job or a green documentation build
alone does not establish deployment; published content must be checked afterwards.

## Limits and rollback

No daemon, edge, collector or operational host was deployed. No release tag or
package was published. Vector configuration/VRL validation does not establish
delivery, ACL access, TLS identity, outage backfill or collector recovery.
Fluent Bit and journal recipes were not exercised against live receivers.
Historical evidence remains dated evidence; this review does not renew old
live-host, release-artifact or recovery claims.

STPA: no new runtime control action or authority; the changes reconcile existing
implementation and document limits. Roll back by reverting the documentation,
comments and site configuration from PR #281, then verify the main Pages redeploy.
