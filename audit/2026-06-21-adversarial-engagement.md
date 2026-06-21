# Assurance engagement — 2026-06-21 (adversarial / red-team pass)

- **Baseline**: `rmednitzer/relay-shell` `main` after PR #103 (SEC-8).
- **Branch**: `claude/adversarial-audit-2026-06-21`.
- **Type**: extremely adversarial, in-depth review — actively attacking the
  trust boundary (get a secret into the audit log, forge audit integrity,
  bypass the deny/tier policy, reach internal services via SSRF, traverse
  paths, forge/confuse OAuth tokens, DoS the audit path), proving claims with
  runnable PoCs. Four red-team work-streams (redaction+audit-integrity,
  policy/exec, SSH/SSRF/DoS, OAuth/HTTP/deploy), synthesised and re-verified on
  the main thread.
- **Posture note**: this is, by design (ADR 0002/0003), an unsandboxed
  full-access shell/SSH server whose safety story is *compensating controls*
  (audit, tiered policy, redaction, bounds), not capability removal. Reaching
  arbitrary hosts, running arbitrary commands, and root/sudo are intended.
  Findings separate **real bugs** from **by-design heuristic residuals** and
  **doc overclaims**.
- **Frozen, point-in-time record** (runbook §8.20). Fixes name the engagement
  PR; deferrals are tracked in `BACKLOG.md`.

---

## Headline: a systemic `\b` word-boundary bug in `patterns.py`

The single most important result. The same Python `\b` mistake — `\b` only
fires at a word↔non-word boundary, so it never matches when the adjacent token
char is preceded by another word char (incl. `_`) — independently broke **two**
trust-boundary controls:

- **Redaction (RED-1, HIGH).** `REDACTION_PREFIX_PATTERNS`' key=value rule was
  `\b(?:…|secret|token|password|…)\s*[:=]\s*\S+`. In the ubiquitous compound
  form `DB_PASSWORD=…`, `APP_SECRET=…`, `API_TOKEN=…` the keyword is preceded
  by `_` (a word char) → `\b` never fired → **the secret value was written to
  the audit log verbatim.** The audit log is precisely what SECURITY.md says
  must never become a secret store.
- **Tier policy (POL-1, MEDIUM).** `TIER2_PATTERN`/`TIER3_PATTERN` opened with
  `\b(`; every alternative starting with a non-word char (`>`, `/`, `:`) was
  therefore dead code. `> /dev/sda` (disk wipe via redirect), the fork bomb
  `:(){ :|:& };:`, and `> /etc/passwd` classified **Tier 1** and were admitted
  in `guarded` mode.

Both fixed in this PR (RED-1 by dropping the leading `\b`; POL-1 by switching
the anchor to `(?<![\w])`, which matches at shell-token starts), with paired
over/under-scrub and positive/near-miss tests, and `PATTERNS_VERSION` 5→6.

---

## Findings register

### Fixed in the engagement PR

| ID | Sev | Title | File | PoC / evidence |
|----|-----|-------|------|----------------|
| RED-1 | **HIGH** | Compound `*_PASSWORD=`/`*_SECRET=`/`*_TOKEN=` secrets leak to the audit log (`\b`) | `patterns.py` keyvalue prefix | `redact("export DB_PASSWORD=prod-p@ss")` was unchanged; now `[REDACTED]`. No FP on `description=`/`--color=auto`/`count=`. |
| AUTH-1 | **HIGH** | OAuth token-type confusion: `Bearer refresh:<tok>` authenticates as an access token for the refresh TTL | `auth/oauth.py:load_access_token` | `load_access_token("refresh:"+r)` returned a valid `AccessToken`; now returns `None` (guard rejects the `refresh:` prefix). |
| POL-1 | MED | Tier dead-patterns: disk-wipe-via-redirect, fork bomb, `>/etc/` classify Tier 1 in guarded | `patterns.py` TIER2/TIER3 | `classify("shell_exec","> /dev/sda")` was Tier 1; now Tier 3. Controls (`rm -rf`, `dd of=/dev/sda`) unchanged; no new FPs (`> /dev/null`, `charm`). |
| RED-2 | MED | ReDoS on the synchronous audit path via the PEM matcher (`.*?` O(n²)) | `patterns.py` PEM | 6400 unterminated `BEGIN` markers: 7.6s → ~1.0s after length-bounding the body; still matches a real key. |
| DOC-1 | overclaim | SECURITY.md implied `--verify-audit` detects in-place tamper without the keyless / off-host caveat | `SECURITY.md` | Hash chain is keyless (ADR 0007); a write-capable attacker recomputes a valid chain. Reworded to require the off-host copy. |
| DOC-2 | overclaim | deployment.md called the deny list "absolute prohibitions"; probe-format footgun undocumented | `docs/deployment.md` | Deny is a regex over `"<tool> <command>"` text → shell-obfuscation/encoding evadable; `^command` anchors silently miss. Reworded to defence-in-depth + probe-format note. |

### Deferred to `BACKLOG.md` (no P0/P1; mostly MEDIUM/LOW hardening + auditability)

| ID | Sev | Title | Note |
|----|-----|-------|------|
| AUTH-2 | MED | Single-client lockdown bypass via re-registration of the existing `client_id` (overwrites `redirect_uri`) | `register_client` allows update when `cid in clients`; fix = refuse any registration once one client exists (verify no legit re-register flow). Attacker needs the client_id + CIDR access. |
| SSH-1 | MED | `known_hosts="ignore"` (per-call MITM downgrade) not recorded in audit args | Add `known_hosts` to `audit_args` for the 5 SSH tools — auditability gap vs CLAUDE.md. |
| SSH-2 | MED | `ssh_check` has no host cap and runs sequentially | `ssh_fanout`/`ssh_keyscan` are capped; add a cap (and/or bounded concurrency). |
| SSH-3 | MED | `SshPool._forwards` unbounded — repeated `ssh_forward` exhausts fds/ports | Add a max-active-forwards cap. |
| SSRF-1 | MED | `ssh_keyscan` deny gate is text-match → evadable by hex/decimal/octal/IPv6-mapped IPs | Normalize literal IPs (no DNS) into the probe so an IP deny catches all encodings; document that hard SSRF blocking needs an egress firewall (DNS-rebinding-proof). |
| RED-3 | MED | Redaction coverage gaps: `AWS_SECRET_ACCESS_KEY=` (keyword mid-name), Azure connection strings/SAS, Slack webhooks, bare GCP creds | Additive patterns + fuzz tests; mid-name keyword needs careful FP control. |
| RED-4 | LOW | `bytes` args bypass `_scrub` (`else: return value`) | Latent — no current wrapper passes `bytes` in audit args; decode+redact defensively. |
| RED-5 | LOW | Dict **keys** not scrubbed (only values) | Low-probability (arg names are developer-chosen). |
| CFG-1 | LOW | `max_output[_hard]`/`*_timeout`/`session_buffer_bytes` have `ge=` but no `le=` upper bound | Operator footgun (env-set 1 TB → clamp never fires); add sane `le=` caps. |
| OBS-1 | LOW | `RELAY_SHELL_AUDIT_PATH=/dev/null` silently discards audit with `degraded=False` | Detect non-regular sink / mark degraded. |
| DEP-1 | LOW | `install-edge.sh` adds the Caddy GPG key without fingerprint pinning (TOFU) | Pin + assert the expected fingerprint before `apt-get install`. |
| DEP-2 | LOW | `/etc/relay-shell` created `0755` (filenames world-listable; content is `0640`) | `install -d -m 0750 -o root -g relay-shell`. |
| EDGE-1 | info | Caddy `/authorize` + `/.well-known/*` handled before the CIDR `@blocked` rule (reachable from any IP) | Correct for browser redirect flows; document, or CIDR-gate if machine-only. |
| EDGE-2 | info | No `Content-Security-Policy` header on the `/authorize` HTML | Add `default-src 'self'` in the Caddyfile header block. |

### Verified BY-DESIGN / not a bug (challenged, held up)

- **Audit hash-chain "forgery".** Keyless by deliberate ADR 0007 tradeoff; a
  write-capable attacker recomputing a clean chain is explicitly acknowledged,
  with the off-host seam as the real control. PoC reproduced; ADR 0007 +
  `verify_chain`/`ChainResult` docstrings are accurate. Only SECURITY.md's
  user-facing wording overclaimed → fixed as DOC-1.
- **Deny/tier heuristic bypass** (shell obfuscation, alternate encodings).
  Documented as "defence in depth, not a sandbox" (policy.py, ADR 0003). The
  *wiring* is sound — every tool routes through `Relay.run`→`policy.check`, and
  the policy-text builders feed each tool's real payload (incl. `script`
  bodies and `env_json` overlays) into the probe. The residual is inherent to
  text-matching; deployment.md wording fixed as DOC-2.
- **Wide-open outbound (SSRF baseline)** — intended fleet posture (ADR 0002).
- **TOFU `accept-new` known_hosts default** — documented; appropriate for a
  fleet tool. (`ignore` per-call is the auditability gap SSH-1, not the default.)
- **Revoke does not cross-revoke access↔refresh** — intentional, **tested**
  opt-out (`test_revoke_*` + docstrings); RFC 7009 leaves it unspecified.
- **`/metrics` unauthenticated** — documented; default-`127.0.0.1` + Caddy
  edge; operator-accepted (SEC-5). Labels are low-cardinality, no secret/arg
  leakage, no injection.
- **MCP resources / prompts bypass `Policy.check`** — documented (server.py
  comment + SECURITY.md §Scope); they expose only the same Tier-0 host
  metadata `ssh_hosts` already returns.
- **No injection in non-shell tools** — `shell_script` via stdin; ssh tools via
  `asyncssh` protocol (no local shell); `ssh_keyscan` validates hosts +
  `shlex.quote` + `--`; transfers/forwards via typed `asyncssh` APIs.
- **Empty `client_id`, PKCE, code replay, refresh rotation single-use,
  lazy expiry** — all PoC-confirmed safe.
- **Log/format injection (jsonl/cef/leef)** — formatters escape `\n`/`\r`/`|`/
  `=`/`\t`; keys are constants; no record-splitting.
- **`_scrub` on int/None/deeply-nested** — no crash/DoS.

## Severity summary

No P0/critical, no remote-unauthenticated RCE, no auth-bypass-without-a-secret.
Two HIGH (a secret-leak and a token-type confusion) — both fixed here. The rest
are MEDIUM/LOW hardening, auditability, DoS-footgun, deploy hygiene, and
documentation accuracy. The core compensating controls (central audit +
redaction, denylist-first wiring, resource bounds, OAuth PKCE/rotation) are
correctly wired; the bugs were in pattern *correctness* (the `\b` class) and one
token-lookup edge, not in the architecture.

## Changes landed in this PR

- `src/relay_shell/patterns.py` — RED-1, POL-1, RED-2; `PATTERNS_VERSION` 5→6.
- `src/relay_shell/auth/oauth.py` — AUTH-1 guard.
- `tests/test_patterns.py`, `tests/test_oauth.py` — paired regression tests.
- `SECURITY.md` (DOC-1), `docs/deployment.md` (DOC-2).
- `BACKLOG.md` / runbook §7.5 — the deferral register above.

Rollback: each fix is small and independently revertible; the redaction/tier
changes are validated against over/under-match and the token guard is a pure
reject — no audit-record-shape or behavior change beyond the intended hardening.

## External references

- OWASP Logging / Secrets Management Cheat Sheets — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html , https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- ReDoS — https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- OAuth 2.0 token revocation (RFC 7009), resource indicators (RFC 8707), bearer usage (RFC 6750)
- GitHub Actions hardening — https://docs.github.com/actions/security-guides/security-hardening-for-github-actions
