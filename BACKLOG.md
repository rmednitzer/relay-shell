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

## 2026-07-15 adversarial + performance pass

Findings from the red-team + profiling pass
([`audit/2026-07-15-adversarial-engagement.md`](audit/2026-07-15-adversarial-engagement.md)),
prompted by "is everything lean, secure, performant?".

Closed (engagement PR):

| ID | Sev | Title | Resolution |
|----|-----|-------|------------|
| RED-6 | HIGH | JSON-quoted-key secret leak in redaction | Quote-tolerant separator + linear char-class value run on the generic + AWS `secret_access_key` rules (`PATTERNS_VERSION` 8). Paired JSON-shape over/under-scrub tests. |
| RED-6a | HIGH | ReDoS introduced by the first RED-6 draft (lookahead O(n²)) | Replaced with a linear char-class matcher; 1 MB scan 165 s → 196 ms. Linearity regression test. |
| P1 | MED | Redaction scanned the full untruncated arg on the event loop | `_scrub_str` bounds the scan to `max_len + 16 KiB`; 1–4 MB arg now constant ~12 ms. Bounded-scan test. Lossless for every truncation-safe pattern — see RED-8 for the one quoted-value edge the original "lossless" claim missed. |
| POL-2 | MED | `TIER3_PATTERN` missed non-obfuscated `rm` long options | Bounded (`{0,16}`) long-option `rm` alternative; positive/negative + ReDoS-ceiling tests. |
| SSH-4 | MED | Deny-list blind to host for `ssh_exec`/`ssh_spawn`/`ssh_fanout`/`ssh_check` | Fold the destination host (canonical-IP widened) into their deny probes; wiring test. |
| BRK-3 | MED | Broker binding omitted SSH identity (`user`/`port`/`key_path`) | Added to `ssh_exec`/`ssh_spawn` audit_args → op-key binding + audit visibility; ADR 0009 follow-up; binding test. |

Closed (post-engagement follow-up review):

| ID | Sev | Title | Resolution |
|----|-----|-------|------------|
| RED-8 | MED | P1 scan-window leaked the tail of a quoted secret past the window | The CLI-flag rule's quoted-value branches required a closing quote and were length-unbounded, so a `--password="…"` value longer than `max_len + 16 KiB` lost its close quote to truncation → the quoted branch failed, the greedy bare fallback stopped at the first internal space, and the post-space tail leaked into the audit record (full-string redaction still caught it, so a P1 regression). Added unterminated-quote fallback branches consuming to end-of-line (`PATTERNS_VERSION` 9); well-formed values byte-identical. Authorization rule verified unaffected (its `$` branch already tolerates truncation). PoC + `test_red8_*` regressions + linearity check. |
| AUTH-3 | LOW | OAuth `exchange_*` re-checked `client_id` but not `expires_at` | `exchange_authorization_code` / `exchange_refresh_token` enforced expiry only via their `load_*` gate, not atomically at exchange — a record valid at load could lapse in the load→exchange window (or a caller could reach exchange without load) and still mint a token (PoC: an expired code and an expired refresh both minted access tokens). Added an `expires_at` re-check after the existing `client_id` re-check in both paths (raise `invalid_grant`, drop the stale record), mirroring the file's defense-in-depth pattern. Not exploitable in the normal SDK flow (load runs first); closes the TOCTOU window. Paired `test_exchange_*_refuses_expired_*` regressions. |

Open deferrals (low-priority perf; measure before acting — none on a hot path):

| ID | Item | Sev | Effort | Rationale | Owner role |
|----|------|-----|--------|-----------|------------|
| PERF-1 | `AuditLogger._emit` does a synchronous file write+flush on the event loop (the read path is already offloaded via `asyncio.to_thread`) | low | S | Local append is fast; offload only if a slow/networked audit sink shows up. Consistency, not a measured stall. | maintainer |
| PERF-2 | `SshPool._sweep_conns` is O(n) over cached connections under one lock per `connect()` | low | S | n is bounded by the connection cache (small); revisit only for very large fleets. | maintainer |
| PERF-3 | `Session.buffer` uses `bytearray` front-deletion (memmove) on overflow/drain | low | S | Buffer is bounded (`session_buffer_bytes`); a deque-of-chunks would avoid the memmove if it ever matters. | maintainer |

## Closed (follow-up work after the audit pass)

Resolved in the backlog-work PRs that followed the 2026-06-12 audit pass.
Do not re-add.

| ID | Title | Resolution |
|---|---|---|
| SEC-1 | `ssh_keyscan` target hosts bypass `RELAY_SHELL_POLICY_DENY` | **Closed** (PR #89). Added `_policy_text_ssh_keyscan(hosts)` and wired it into the wrapper so the deny list gates scan targets; the call is audited `denied=True` on a match. The tier-over-classification tradeoff was accepted (only bites `guarded` mode; `open` is advisory, `readonly` already refuses Tier 1; `POLICY_ALLOW` is the escape hatch; consistent with the transfer tools) and is documented in the builder docstring. Tests: deny-gates-host, non-denied-host-runs, classifier-tradeoff pin, and the R-002 builder-contract line. |
| QUAL-1 | A few `seccomp` termination tests assert via "does not hang" | **Closed** (PR #89). Added explicit observable asserts to the five control-flow tests (`m._count == 0` after a drain break, `== 1` after isolated dispatch, `is None` for the suppressed-ioctl `_respond_continue`). Test-only. |
| TOOL-1 | gitleaks flags synthetic redaction fixtures as secrets | **Closed** (PR #89). Added a tightly-scoped `.gitleaks.toml` (extends the default ruleset) allowlisting only `tests/*.py`, `docs/runbook.md`, and `audit/*.md`. Validated: history scan drops from 13 leaks to 0, while a canary key planted under `src/` is still caught. The CI job that consumes it landed as TOOL-3. |
| TOOL-3 | A CI secret-scan job (gitleaks) | **Closed** (PR #90). Added `.github/workflows/gitleaks.yml` (push to main, PRs, daily, `workflow_dispatch`). Self-contained, supply-chain careful: pinned gitleaks 8.30.1 installed by discovering the exact asset name from the release's own checksums file and verifying the tarball before extracting (no hardcoded checksum, no third-party action / license endpoint); `permissions: contents: read`; `gitleaks detect -c .gitleaks.toml` fails the job on any finding. Validated: YAML parses, the detect command runs clean on the tree, the install asset-discovery + checksum-verify pipeline was dry-run (match OK, tamper FAILS), and both first live runs (PR #90 and the post-merge push to `main`) concluded `success`. The required-check decision was made and applied on 2026-06-12: `gitleaks (secret scan)` is now a required status check on `main` via the `main-protection` ruleset (see the F-G2 row below). |
| SEC-2 | `dependency-review.yml` re-enables `persist-credentials` | **Closed** (PR #91). Removed the checkout step from the job entirely. Source-verified at the pinned action SHA (`a1d282b`, v5.0.0): for `pull_request` events the action takes base/head SHAs from the event payload (`src/git-refs.ts`) and calls the Dependency Graph compare API (`src/main.ts`); it spawns no git process and never reads the working tree unless a local `config-file` input is used (none is). The recorded "shells out to `git fetch`" rationale does not match this version's source. No checkout means no persisted token and no repo bytes on disk. Self-validated: the change runs on its own PR's `dependency-review` check. |
| REL-1 | Starlette `TestClient` deprecation in `tests/test_metrics.py` | **Closed** (PR #92). The "install httpx2" warning came from `starlette.testclient`, not from needing httpx 2 — re-checked this session: driving `/metrics` through httpx's own `ASGITransport` (already pinned, httpx 0.28.1) returns the identical response with **zero** warnings, and the `/metrics` custom route needs no lifespan context. Migrated the four HTTP `/metrics` tests off `starlette.testclient.TestClient` to a small `_http_get` ASGITransport helper. Suite now reports 0 warnings (was 1); `pytest -W error::DeprecationWarning tests/test_metrics.py` passes. No httpx2 bump, no dependency change. The earlier "blocked on upstream" disposition was wrong. |
| TOOL-2 | ruff pin skew across `requirements.txt` / `.pre-commit-config.yaml` / the `dev` extra resolve | **Closed** (PR #93; accepted as designed, evidence-verified — a disposition, no code change). `renovate.json5` enables the `pre-commit` manager and groups `pip_requirements` updates on the weekly schedule, and the history shows it updating both pinned locations in practice (#83 pre-commit ruff `v0.15.16`, #84 python dependencies, #85 pre-commit `v6`). The skew window is therefore bounded by the weekly Renovate cadence, both versions lint the tree identically, and a manual pin would only fight the bot. No change needed; re-open only if a ruff release ever splits lint behavior inside one cadence window. |

## 2026-06-21 full audit pass

Findings from the 2026-06-21 full validation + security audit
([`audit/2026-06-21-engagement.md`](audit/2026-06-21-engagement.md)). The scanner
battery (pip-audit, trivy, bandit, semgrep, actionlint, shellcheck, gitleaks) was
clean and no pinned dependency carries a known CVE; there were no P0/P1 findings.

Closed (engagement PR + 2026-06-21 follow-up PRs):

| ID | Title | Resolution |
|---|---|---|
| SEC-3 | `pyproject.toml` dependency lower bounds below patched minimums | **Closed** (this PR). Floors raised: `asyncssh>=2.23.0` (GHSA-g794-3fmp-753h), `starlette>=1.3.0` (BadHost GHSA-86qp-5c8j-p5mr / GHSA-jp82-jpqv-5vv3), `PyJWT>=2.13.0` (HMAC confusion GHSA-xgmm-8j9v-c9wx), `cryptography>=48.0.1` (GHSA-537c-gmf6-5ccf). The pinned set was already safe; this codifies minimum-safe transitive versions, mirroring PR #97's `pydantic-settings` floor. Installed/tested set unchanged; gate green. |
| TOOL-4 | CODEOWNERS required review on a non-existent `/.github/dependabot.yml` | **Closed** (this PR). The repo uses Renovate; reference corrected to `/renovate.json5`. |
| SEC-4 | Add Anthropic `sk-ant-` + HuggingFace `hf_` redaction shapes | **Closed** (follow-up PR to the 2026-06-21 audit pass). Added whole-match patterns to `patterns.py` (`sk-ant-[A-Za-z0-9_-]{20,}`, `hf_[A-Za-z0-9]{34,}`), bumped `PATTERNS_VERSION` 4→5, added paired over/under-scrub tests in `tests/test_patterns.py`, and updated the `redaction.py` docstring + `SECURITY.md`. Gate green incl. the `redact` idempotency fuzz. |
| CI-1 | `release.yml` verify job persisted the workflow token unnecessarily | **Closed** (P2/P3 follow-up PR). `persist-credentials: true` → `false`; no git-auth step runs after checkout (the tag signature is verified via the REST API with an explicit `GH_TOKEN`). actionlint clean. |
| CI-2 | `sbom.yml` shell interpolation + workflow-wide `contents: write` | **Closed** (P2/P3 follow-up PR). Event/tag values now pass through env vars instead of `${{ }}` in `run:`; the workflow token defaults to `contents: read` with a job-level `contents: write` escalation. actionlint clean. |
| SEC-6 | `oauth.load_refresh_token` read without the per-provider lock | **Closed** (P2/P3 follow-up PR). Wrapped the read in `async with self._lock` like every other store access; verified no lock-holding path calls it (no nested-acquire deadlock). |
| SEC-7 | OAuth RFC 8707 `resource` not forwarded to the SDK `AuthorizationCode` | **Closed** (P2/P3 follow-up PR). `_build_auth_code` now forwards `resource` (the field exists in mcp 1.27.2); `.get` keeps back-compat. Test `test_authorization_code_forwards_resource`. |
| FMT-1 | LEEF formatter omitted the mandatory LEEF 2.0 delimiter field | **Closed** (P2/P3 follow-up PR). `_format_leef` now emits `…\|audit\|x09\|<ext>`; `tests/test_audit.py` updated. |
| QUAL-2 | `ssh_forward` spec parse leaked a raw `ValueError` | **Closed** (P2/P3 follow-up PR). Extracted `SshPool._parse_forward_spec` (validated before connecting) raising a bounded message; paired unit test. |
| DOC-4 | `CHANGELOG.md` `[Unreleased]` duplicate `### Security` / `### Changed` blocks | **Closed** (P2/P3 follow-up PR). Consolidated to one block per category (Added/Changed/Fixed/Security) via a content-preserving regroup; Keep a Changelog 1.1.0. |
| SEC-8 | OAuth token-dir `chmod(0o700)` was best-effort | **Closed** (SEC-8 follow-up PR). `_Store` now creates the dir with `mode=0o700` (private at creation; umask can only tighten 0o700), still tightens a pre-existing dir best-effort, and then **fails closed only if the dir remains group/other-accessible**. An exposed token store is refused, while a correctly-`0o700` dir owned by another uid (which we cannot chmod) still passes — so the earlier deferral's false-break concern does not arise. Test `test_state_dir_permission_enforcement` covers both the refuse and accept paths; `test_state_dir_and_files_are_private` still green. |
| FMT-2 | CEF header field values not passed through an escaper | **Closed** (config/audit-hardening PR). `_format_cef` now builds the header (`vendor\|product\|version\|sig\|name\|severity`) via a new `_cef_header_escape` (escapes `\` and the `\|` separator, not `=`). The fields are constants so the bytes are byte-identical (pinned by `test_audit_cef_format`); the escape is structural insurance against a future dynamic header field splitting a record. Test `test_cef_header_escape_neutralizes_pipe_and_backslash`. |
| CI-3 | `sbom.yml` artifacts not SLSA-attested | **Closed** (sbom-attest PR). The `sbom` job gained `id-token: write` + `attestations: write` and an `actions/attest-build-provenance` (SHA-pinned v4) step over both `.cdx.{json,xml}` files, mirroring `release.yml`'s wheel attestation. Each SBOM now carries a Sigstore-signed in-toto provenance record in the public transparency log (verify with `gh attestation verify`). actionlint clean. |

Open deferrals (severity order; smaller effort first):

| ID | Item | Sev | Effort | Rationale / approach | Owner role |
|---|---|---|---|---|---|
| DOC-5 | `CHANGELOG.md` lacks Keep-a-Changelog version-compare links | info | XS | Deferred until a second release is tagged ("omit rather than fake"). | maintainer |

Accepted as-designed / operator discretion (no action): **SEC-5** (`/metrics`
OAuth bypass) — operator decision (2026-06-21): keep the documented design
(default `http_host=127.0.0.1` bind + Caddy-edge firewall), not gated in-app, so
the standard unauthenticated Prometheus-scrape model is preserved; pre-commit
hooks pinned
to tags (Renovate-managed; TOOL-2 rationale); hygiene bumps `cryptography` 49 /
`anyio` 4.14 / `mcp` 1.28 (Renovate); `RestrictSUIDSGID` absent from the systemd
hardening drop-in (ADR 0002 full-capability posture; operator call); the ADR 0006
hybrid status string and ADR 0005's frozen "next free 0006" line
(no-retro-edit-of-decision-records).

## 2026-06-21 adversarial (red-team) pass

Findings from the extremely-adversarial follow-up review
([`audit/2026-06-21-adversarial-engagement.md`](audit/2026-06-21-adversarial-engagement.md)),
which actively attacked the trust boundary (get a secret into the audit log,
forge audit integrity, bypass the deny/tier policy, SSRF, path traversal, OAuth
token confusion, DoS the audit path) with runnable PoCs. No P0/critical, no
remote-unauthenticated RCE, no auth-bypass-without-a-secret. Two HIGH (a
secret-leak and a token-type confusion), both fixed in the engagement PR; the
rest are MEDIUM/LOW hardening, auditability, DoS-footgun, deploy hygiene, and
doc accuracy.

Headline: a single Python `\b` word-boundary mistake (it only fires at a
word↔non-word boundary, so it never matches when the adjacent token char is
preceded by another word char incl. `_`) independently broke **two**
trust-boundary controls — redaction (RED-1) and tier classification (POL-1).

Closed (engagement PR):

| ID | Sev | Title | Resolution |
|---|---|---|---|
| RED-1 | **HIGH** | Compound `*_PASSWORD=`/`*_SECRET=`/`*_TOKEN=` secrets leaked to the audit log | **Closed** (this PR). Dropped the leading `\b` from the `key=value` redaction prefix in `patterns.py`; the trailing `\s*[:=]\s*\S+` still gates it to assignment shapes (no over-match on plain words). `PATTERNS_VERSION` 5→6. Paired over/under-scrub tests in `tests/test_patterns.py` (no FP on `description=`/`--color=auto`/`count=`). |
| AUTH-1 | **HIGH** | OAuth token-type confusion: `Bearer refresh:<tok>` authenticated as an access token for the refresh TTL | **Closed** (this PR). `load_access_token` now rejects any bearer string carrying the `refresh:` key prefix before the store lookup. Test `test_load_access_token_rejects_refresh_prefixed_bearer`. |
| POL-1 | MED | Tier dead-patterns: disk-wipe-via-redirect (`> /dev/sda`), fork bomb, `>/etc/` classified Tier 1 in `guarded` | **Closed** (this PR). `TIER2_PATTERN`/`TIER3_PATTERN` anchor switched `\b(` → `(?<![\w])(` so alternatives starting with a non-word char fire at shell-token starts. Controls (`rm -rf`, `dd of=/dev/sda`) unchanged; no new FP (`> /dev/null`, `charm`). Pinned by `tests/test_patterns.py`. |
| RED-2 | MED | ReDoS on the synchronous audit path via the PEM matcher (`.*?` → O(n²) on many unterminated `BEGIN` markers) | **Closed** (this PR). Length-bounded the PEM body (`[\s\S]{0,8192}?`); still matches a real key block. 6400-marker input 7.6s → ~1.0s; regression timing guard in `tests/test_patterns.py`. |
| DOC-1 | overclaim | `SECURITY.md` implied `--verify-audit` detects in-place tamper without the keyless / off-host caveat | **Closed** (this PR). Reworded to state the chain is keyless (ADR 0007) and a write-capable attacker recomputes a valid chain — the off-host copy is the real control, required not optional where audit integrity is load-bearing. |
| DOC-2 | overclaim | `docs/deployment.md` called the deny list "absolute prohibitions"; probe-format footgun undocumented | **Closed** (this PR). Reworded to defence-in-depth (not a sandbox); documents the `"<tool> <command>"` probe shape and that a regex over that text is shell-obfuscation/encoding-evadable and `^command` anchors silently miss. |

Closed in follow-up PRs (2026-06-21 adversarial backlog work):

| ID | Sev | Title | Resolution |
|---|---|---|---|
| SSH-1 | MED | `known_hosts="ignore"` (per-call MITM downgrade) not recorded in `audit_args` | **Closed** (SSH-hardening PR). The 5 SSH tools (`ssh_exec`/`ssh_spawn`/`ssh_upload`/`ssh_download`/`ssh_forward`) now record the effective per-call host-key verification mode (`known_hosts or settings.ssh_known_hosts`) in `audit_args`, so a per-call `ignore` downgrade is visible in the audit trail. Test `test_ssh_tools_record_known_hosts_in_audit`. |
| SSH-2 | MED | `ssh_check` has no host cap and runs sequentially | **Closed** (SSH-hardening PR). Added a per-call host cap (`_SSH_CHECK_MAX_HOSTS=100`, bounded error like `ssh_fanout`) and bounded-concurrency probing (`_SSH_CHECK_CONCURRENCY=8`, output order preserved). Test `test_ssh_check_caps_host_count`. |
| SSH-3 | MED | `SshPool._forwards` unbounded — repeated `ssh_forward` exhausts fds/ports | **Closed** (SSH-hardening PR). Added `RELAY_SHELL_MAX_FORWARDS` (default 64, `ge=1, le=1024`, mirroring `max_sessions`); `add_forward` pre-checks before dialling and re-checks under the lock (closing the just-opened listener on a lost race) so the cap is never exceeded and nothing leaks. New `ForwardError`; surfaced in `server_info.config.max_forwards`. Test `test_add_forward_enforces_cap`. |
| SSRF-1 | MED | `ssh_keyscan` deny gate evadable by hex/decimal/octal/IPv4-mapped IP encodings | **Closed** (SSRF PR). `_policy_text_ssh_keyscan` now appends the canonical dotted/colon form of any literal IP in the target list (`_canonical_ips` / `_augment_probe_with_ips`, via `inet_aton` + `ipaddress`, **no DNS**), so an IP-based `RELAY_SHELL_POLICY_DENY` catches every spelling of the same address. Purely additive to the probe. `deployment.md` updated: hostnames/DNS-rebinding still need an egress firewall. Tests in `tests/test_ssh_keyscan_tool.py`. |
| AUTH-2 | MED | Single-client lockdown bypass via re-registration of the existing `client_id` (overwrites `redirect_uri`) | **Closed** (OAuth PR). `register_client` previously refused only a *new* `client_id` under lockdown (`cid not in clients`), so the existing client could be re-registered with an attacker `redirect_uri`. Now any registration that would create *or modify* a client under lockdown is refused (`clients.get(cid) != incoming`); a byte-identical re-registration stays a harmless no-op so a client re-running DCR is not broken. Tests `test_single_client_lockdown_refuses_redirect_uri_overwrite` / `_allows_identical_reregistration` / `test_non_lockdown_still_allows_client_update`. |
| RED-3 | MED | Redaction coverage gaps (AWS secret access key, Azure conn-string/SAS, Slack webhooks, GCP creds) | **Closed** (redaction PR). New structure-preserving prefixes: AWS `*_SECRET_ACCESS_KEY=` (phrase-anchored on `secret_access_key` for FP control, since the keyword is mid-name), Azure `AccountKey=`/`SharedAccessKey=`, and Azure SAS `?…&sig=` (anchored on `[?&]` + 20-char floor). New whole-match: Slack incoming-webhook URLs (distinct from `xox*`). GCP service-account creds need no new rule — their only secret is the `private_key` PEM block, already collapsed by the PEM rule (matches a JSON-embedded block with escaped `\n` too). `PATTERNS_VERSION` 6→7; `redaction.py` docstring + `SECURITY.md` updated. Paired over/under-scrub tests in `tests/test_redaction.py`; `redact` idempotency/no-leak fuzz still green. |
| RED-4 | LOW | `bytes` args bypass `_scrub` (`else: return value`) | **Closed** (redaction PR). `_scrub` now decodes `bytes` (utf-8, `errors="replace"`, never raises) and scrubs it as a string, so a future caller cannot smuggle a secret past redaction as raw bytes. Test `test_red4_bytes_args_are_decoded_and_redacted`. |
| RED-5 | LOW | Dict **keys** not scrubbed (only values) | **Closed** (redaction PR). `_scrub` now redacts dict keys as well as values — a nested, caller-supplied dict could carry a secret in a key. Test `test_red5_dict_keys_are_scrubbed`. |
| CFG-1 | LOW | `max_output[_hard]` / `*_timeout` / `session_buffer_bytes` had `ge=` but no `le=` upper bound | **Closed** (config/audit-hardening PR). Added generous `le=` caps to `max_output` (16 MiB), `max_output_hard` (128 MiB), `default_timeout` / `max_timeout` / `session_idle_timeout` (24 h), and `session_buffer_bytes` (16 MiB), so an absurd env value is rejected at load instead of yielding a clamp that never bites. Test `test_limit_upper_bounds_reject_absurd_values`. |
| OBS-1 | LOW | `RELAY_SHELL_AUDIT_PATH=/dev/null` silently discarded audit with `degraded=False` | **Closed** (config/audit-hardening PR). `AuditLogger` now flags `degraded=True` (with a reason) when the sink is not a regular file (`/dev/null`, a device, a FIFO), so the `relay_shell_audit_degraded` gauge and `server_info.audit` surface "audit goes nowhere" instead of reporting healthy. The sink still points where configured. Test `test_audit_degrades_on_non_regular_sink`. |
| DEP-1 | LOW | `install-edge.sh` added the Caddy GPG key trust-on-first-use | **Closed** (deploy-hardening PR). The repo key is now dearmored to a temp file; the installer logs its fingerprint and, if `RELAY_SHELL_EDGE_CADDY_GPG_FPR` is set, **fails closed** unless it matches before apt trusts the key. No default fingerprint is shipped (Caddy/cloudsmith publish no canonical one to verify against), so the operator pins the value they confirm at caddyserver.com/docs/install; unset = unpinned with a warning. `deployment.md` env-var table updated. |
| DEP-2 | LOW | `/etc/relay-shell` created `0755` (world-listable) | **Closed** (deploy-hardening PR). Both installers now `install -d -m 0750 -o root -g relay-shell /etc/relay-shell` (edge installer falls back to `0750 root:root` on an edge-only host without the group). systemd reads the EnvironmentFiles as root, so dropping the world bit does not affect the service. |
| EDGE-1 | info | Caddy `/authorize` + `/.well-known/*` reachable from any IP (before the CIDR rule) | **Closed** (deploy-hardening PR; documented as intended). Expanded the Caddyfile comment: the browser OAuth redirect + RFC 8414 discovery must be reachable pre-token, `/authorize` still needs a registered client + PKCE, and tool traffic + `/token` stay CIDR-gated. Documents how to move the three handles below `@blocked` for a machine-only (no-browser) deployment. |
| EDGE-2 | info | No `Content-Security-Policy` on the `/authorize` HTML | **Closed** (deploy-hardening PR). Caddyfile header block now sets `Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"`. CSP only affects HTML rendering (inert for JSON tool/token responses); a comment notes how to relax it for a customized authorize page. Drift guard `test_caddyfile_sets_content_security_policy`. |
| SSRF-2 | LOW | IP-encoding bypass also applied to the other host-bearing deny probes | **Closed** (SSRF-2 PR). Extracted a shared `_with_canonical_ips(text, *hosts)` helper (SSRF-1's keyscan path now delegates to it) and applied it to `_policy_text_ssh_upload`/`_ssh_download` (the `host` arg) and `_policy_text_ssh_forward` (the `L:/R:` dhost, via a lenient `_forward_dhost`). An IP-based `RELAY_SHELL_POLICY_DENY` now catches a decimal/hex/octal/IPv4-mapped destination on the transfer/forward tools too, not just `ssh_keyscan`. Tests in `tests/test_tool_wrappers.py`. |

Open deferrals (severity order; smaller effort first):

_(none — all adversarial-pass deferrals closed.)_

Verified BY-DESIGN / not a bug (challenged, held up — no action): audit
hash-chain "forgery" (keyless by ADR 0007; off-host seam is the control;
only the SECURITY.md wording overclaimed → DOC-1); deny/tier heuristic
bypass via shell obfuscation / alternate encodings (defence-in-depth, not a
sandbox — policy.py / ADR 0003; wiring is sound, residual is inherent to
text-matching → DOC-2); wide-open outbound / SSRF baseline (intended fleet
posture, ADR 0002); TOFU `accept-new` known_hosts default (documented;
`ignore` per-call is the SSH-1 auditability gap, not the default);
revoke not cross-revoking access↔refresh (intentional, **tested** opt-out;
RFC 7009 leaves it unspecified); `/metrics` unauthenticated (SEC-5,
operator-accepted); MCP resources/prompts bypassing `Policy.check` (documented;
expose only Tier-0 host metadata); no injection in the non-shell tools
(`asyncssh` protocol, stdin, `shlex.quote` + `--`); log/format injection
(formatters escape `\n`/`\r`/`|`/`=`/`\t`; constant keys); empty `client_id` /
PKCE / code-replay / refresh single-use / lazy expiry (PoC-confirmed safe).

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
| F-G2 | Branch protection on `main` — **fully resolved** (rules enumerated and hardened) | high (governance), now closed | S (done) | Prior packs (`audit/2026-06-01-engagement.md` §7.1) carried this as an open HIGH item ("`main` accepts direct pushes"). Resolved in two steps. 2026-06-12 (audit pass): the branches API reports `protected: true` [V]. 2026-06-12 (follow-up, via the Vertex-held `gh` credential): protection comes from ruleset `main-protection` (id 17307996; classic protection is unset), which enforced pull_request (0 approvals), non_fast_forward, deletion, and required_linear_history [V]. With operator confirmation (a T3 change per the operator's `github-vertex.md` contract), the ruleset gained `required_status_checks` — `check (py3.12)` / `check (py3.13)` / `check (py3.14)` / `gitleaks (secret scan)`, all bound to GitHub Actions, strict=false — and `required_signatures` (closing the prior pack's deferred **P2-3**). Verified effective post-change via `GET /repos/rmednitzer/relay-shell/rules/branches/main` [V]. pip-audit / dependency-review / CodeQL stay advisory by operator choice. | repo owner (executed with operator confirmation) |

## 2026-07-15 full audit + Vertex/Axiom comparison pass

Findings and lessons from the 2026-07-15 pass
([`audit/2026-07-15-engagement.md`](audit/2026-07-15-engagement.md)). The
scanner battery (pip-audit, trivy vuln+secret, bandit, semgrep, actionlint,
shellcheck) was clean and no pinned dependency carries a known CVE; there were
no P0/P1 findings. The pass compared `relay-shell` against two sibling MCP
control planes and turned the highest-value lesson (L1) into shipped code.

Closed (engagement PR):

| ID | Title | Resolution |
|---|---|---|
| L1 (broker) | No per-call confirmation for irreversible ops | **Closed** (this PR). Implemented the opt-in Tier-3 confirmation broker: [ADR 0009](docs/adr/0009-tier3-confirmation-broker.md), `src/relay_shell/broker.py` (100% covered), `operation_confirm` tool (contract 21 → 22), `action=confirm_plan`/`confirm_execute` audit markers, `server_info.confirm` block. Default-off byte-identical; layered after the deny/mode check. |
| DOC-1 | Living docs named the superseded pin (`mcp==1.27.2` / `asyncssh` 2.23.1) after Renovate moved it to `mcp==1.28.1` / `asyncssh==2.24.0` | **Closed** (this PR). Reconciled the README status line + compatibility matrix and the `docs/architecture.md` diagram; "last validated" → 2026-07-15. Frozen ADRs / prior engagement records left intact per convention. |
| ENV-1 | `.env.example` missing `RELAY_SHELL_CONFIRM_TIER3` / `RELAY_SHELL_CONFIRM_TTL` | **Closed** (PR #129). Added the two commented vars mirroring `docs/deployment.md` §8a (this session couldn't edit `.env*` paths; done in a follow-up). |
| DOC-6 (L3) | No deploy-host HIDS / config-drift guidance | **Closed** (DOC-6 PR). `docs/deployment.md` §3a "Host integrity + config-drift monitoring" documents etckeeper / AIDE / fail2ban / lynis as detection compensating for the intentionally-partial systemd confinement. Docs only. |
| AUD-1 (L2) | No in-band audit verify / correlate tool | **Closed as a split disposition** (AUD-1 PR), after evaluating the lesson against ADR 0007 + the actual audit schema. **Shipped:** read-only triage filters on `audit_tail` (`tool`/`tier`/`denied`, Tier 0, tool contract unchanged) — the operator-diagnostic use case that already justifies `audit_tail`. **Declined:** in-band chain-*verify* stays the CLI `--verify-audit` (ADR 0007 — the audited model must not drive verification of its own trail). **N/A:** correlate-by-input-`sha256` — relay-shell hashes the *output*, not the input, so there is no input hash to correlate on. |

Open deferrals (severity order; smaller effort first):

| ID | Item | Sev | Effort | Rationale / approach | Owner role |
|---|---|---|---|---|---|
| OPS-2 (L4) | `pip-audit` has no KEV/EPSS exploit prioritization | info | S | Lesson from the comparison: layer Known-Exploited / EPSS signal on top of the existing `pip-audit` gate for prioritization. Advisory only — `pip-audit` already fails closed. Low value for the small pinned set; revisit if the dependency set grows. | maintainer |

## Notes on items NOT added here

- No critical / high / medium **code** security findings were produced by
  this pass, so there is no remediation backlog of that kind.
- The structural refactor candidates (`R-001` table-driven tool registration,
  `R-004` OAuth store `Protocol`) already live in runbook §5.2 and are not
  duplicated here.
- No destructive or irreversible operation was proposed by this pass
  (no history rewrite, no dependency major bump, no schema change), so the
  charter's "proposals, not executed" bucket is empty.
