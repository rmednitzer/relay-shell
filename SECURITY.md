# Security policy: relay-shell

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/rmednitzer/relay-shell/security/advisories/new).
Do not post exploit payloads, secrets, personal data or sensitive operational
details in public issues. If private reporting is unavailable, use an existing
maintainer security contact where published; otherwise request a private channel
with a minimal, non-sensitive issue. Do not assume an invented email address works.

Include the affected revision/version and paths, prerequisites and trust boundary,
expected versus actual behavior, a minimal sanitized reproduction, impact and any
workaround. Use synthetic data. A dependency issue affecting this project is in
scope: coordinate upstream as appropriate without delaying notification here.
This policy does not authorize testing third-party or live deployments, service
disruption, credential use, persistence or access to other people's data.

Existing response targets are retained below as maintainer goals, not guaranteed
service levels. Coordinate disclosure and advisory timing with the maintainer;
urgent active exploitation or credential exposure should be identified immediately.

## Contributor security requirements

Follow [AGENTS.md](AGENTS.md) for secure coding, dependency/CI integrity, verification,
STPA and threat-analysis requirements. Preserve deployment trust boundaries and
document exceptions, residual risk and recovery. Never suppress a security finding
merely to pass CI. For fixes, capture a reproducer, add a meaningful regression,
check adjacent paths, assess affected versions and coordinate remediation/advisories.
Code review and CI do not prove deployed configuration or legal compliance.

## Model

`relay-shell` is operator infrastructure. It deliberately runs **without an internal
sandbox** and executes commands with the full privileges of its service
account. That is the point of the tool; see
`docs/adr/0002-no-sandbox-full-access.md`. Security is achieved by
**compensating controls** and by **deployment discipline**, not by
constraining the executor.

### Trust boundary

The trust boundary is the MCP transport. Treat everything arriving over it as
potentially attacker-influenced (prompt injection through tool results, file
contents, or remote command output). The controls below reduce risk within the deployment posture. Command classification
and redaction are heuristic; arbitrary shell execution is not a containment boundary:

- **Tiered authority** (`docs/adr/0003-tiered-authority.md`). Every call is
  classified Tier 0 (read-only) to Tier 3 (irreversible). `RELAY_SHELL_POLICY_MODE`:
  - `open` (default): full access, every call still classified and audited.
  - `guarded`: Tier 2+ refused unless `RELAY_SHELL_POLICY_ALLOW` matches.
  - `readonly`: only Tier 0 permitted.
  `RELAY_SHELL_POLICY_DENY` is always enforced first, in every mode.
- **Append-only audit** (`audit.jsonl`). One JSON object per line:
  timestamp, tool, redacted/truncated args, SHA-256 of the output, output
  byte length, exit code, request id, client id, tier. The output **body is
  never written** - only its hash and length. Make the file append-only on
  disk (`chattr +a`) and ship it off-host; the bundled logrotate config
  preserves the attribute across rotation. See
  [`docs/audit-shipper.md`](docs/audit-shipper.md) for worked Vector,
  Fluent Bit, and `systemd-journal-remote` recipes. Optionally set
  `RELAY_SHELL_AUDIT_CHAIN=true` for a per-record hash chain
  (`docs/adr/0007-audit-hash-chain.md`) so a *naive* in-place edit,
  insertion, reorder, or interior deletion is detectable with
  `relay-shell --verify-audit`. The chain is **keyless** by deliberate
  design (ADR 0007): it is in-record tamper-evidence against accidental or
  unsophisticated corruption and does not depend on the filesystem attribute
  the residual-risk attacker below can clear — but it is **not** a defence
  against an attacker who can both rewrite the log and recompute the chain
  from genesis. That attacker is caught only by the off-host copy (compare
  the cross-rotation seam: the prior file's last `chain` against the next
  file's first `prev`), so off-host shipping is required, not optional, where
  audit integrity is load-bearing. `relay-shell --verify-audit` is fail-closed: a missing / empty
  log or a head-truncated chain (a non-genesis start) fails by default, so
  the check never blesses an absent or front-excised trail; `--segment`
  accepts a legitimate mid-stream rotation segment. Tail-truncation and
  cross-file durability remain the off-host shipper's job (a single file
  cannot prove its own newest record is the true end). The bundled
  `deploy/evidence/` verifier checks every retained segment and the seams between
  them and gates the off-host copy on the result (it tolerates logrotate pruning the
  oldest segments, see its README for what that does and does not detect). A runtime
  write failure marks the audit sink degraded rather than silently dropping records.
- **Secret redaction.** Audited arguments are scrubbed for bearer tokens,
  API keys, private-key blocks, `Authorization` headers, long-name CLI
  flags (both `--password` and single-dash `-token=` forms, including
  PowerShell `-Credential VALUE` and the `ConvertTo-SecureString '...'
  -AsPlainText` inline-secret idiom — WIN-1 / ADR 0011),
  URL-embedded credentials, cloud-provider assignment forms (AWS
  `*_SECRET_ACCESS_KEY=`, Azure connection-string `AccountKey=`/
  `SharedAccessKey=` and SAS `sig=`), and a set of structurally-anchored
  provider token shapes (Google `AIza`/`ya29.`, Stripe `sk_`/`rk_`, GitLab
  `glpat-`, npm `npm_`, PyPI `pypi-`, GitHub `gh*_`, OpenAI `sk-`, Anthropic
  `sk-ant-`, HuggingFace `hf_`, AWS `AKIA`, Slack `xox*` tokens and
  incoming-webhook URLs, and JWTs) that are
  collapsed even when they arrive bare in a JSON body or log line. Anchors track the canonical
  secret-scanning rulesets; each is keyed on prefix + length, never on
  the value's character class. Audited arguments that arrive as raw `bytes`
  are decoded and scrubbed too, and redaction is applied to dict **keys** as
  well as values. The compact short-form
  `-p<value>` is intentionally redacted only for MySQL-family commands
  (`mysql`, `mariadb-dump`, `mycli`, ...) because `-p` is overloaded
  elsewhere (`ssh -p22`, `nmap -p1-1000`); operators putting passwords
  inline should use `--password=...` or `~/.my.cnf` instead. Quoted
  multi-word values (`PASSWORD="a b c"`, `{"password": "a b c"}`), hyphenated
  secret flags (`--client-secret V`, `--access-token V`, `--passphrase V`),
  `curl -u user:pass`, `sshpass -p`, `docker login -p`, `openssl -pass pass:`
  and URL passwords containing `@` are covered. A password containing `/` in a
  URL cannot be told from a path and is not redacted. Compound key variables
  (`SECRET_KEY=`, `DJANGO_SECRET_KEY=`, `ENCRYPTION_KEY=`, `PRIVATE_KEY=`,
  `ACCESS_KEY=`, `SIGNING_KEY=`, `*_KEY_BASE=`) and PGP private-key blocks are covered;
  positional secrets with no keyword, `password := V` forms and URL user-info tokens with
  no colon are not. **Input typed into a PTY
  session** has no keyword for any of this to find, so `session_send` input is
  withheld from the audit record when the session is at a secret prompt (the last
  output line reads like one, or the terminal has echo off), and
  `RELAY_SHELL_AUDIT_SESSION_INPUT=hash` records only its length and SHA-256 for
  deployments that must never log typed content (at a recognised secret prompt the digest
  is withheld too, since an unsalted hash of a password can be brute-forced). A secret typed at a prompt this
  heuristic does not recognise is still recorded. See
  `src/relay_shell/redaction.py` for the full pattern set.
- **OAuth client approval.** Dynamic registration is open and the authorization
  endpoint has no login step, so a registered client could previously obtain tokens
  with no operator involvement (and a corrupt `clients.json` reopened registration).
  New clients are now *pending* until the operator approves them on the host
  (`relay-shell --auth-approve`; `RELAY_SHELL_AUTH_REQUIRE_APPROVAL`, default on),
  existing clients are carried over as approved at upgrade, and an unparsable state
  file fails closed. See `docs/auth.md` (Operator approval).
- **SSH host identity.** Host keys are verified: `RELAY_SHELL_SSH_KNOWN_HOSTS` is `strict`
  (known hosts only), `accept-new` (trust on first use; a changed key is refused) or
  `ignore` (never verifies). A caller may pass a weaker `known_hosts` per call unless
  `RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false`; the audit record states the mode actually
  used. Jump hosts are verified against `~/.ssh/known_hosts`. Local (`L`) and dynamic (`D`)
  forwards listen on loopback only.
- **SSH target tokens.** A caller-supplied host, `user` or `jump` hop must be a plain token
  (no whitespace, quotes or leading `-`) or the call is refused. asyncssh substitutes them
  into an `ssh_config` `ProxyCommand` (`%h`, `%n`, `%r`) and splits the result into argv, so
  a host such as `x -oProxyCommand=...` would otherwise run a local command; operator-written
  inventory and `ssh_config` aliases are trusted as written.
- **Resource bounds.** Per-call timeout and output caps, a bounded number of
  concurrent sessions, bounded per-session buffers, and idle/lifetime
  reaping. Failure paths return a structured error string; a tool never
  raises into the transport.
- **Optional OAuth 2.1 edge** (HTTP transport): dynamic
  client registration with single-client lockdown, PKCE, file-backed
  access/refresh tokens (stored hashed, never raw) with rotation and expiry. **Opt-in, disabled by
  default** (`RELAY_SHELL_AUTH_ENABLED=false`); enable it for any HTTP exposure
  beyond a trusted loopback + edge. See [`docs/auth.md`](docs/auth.md) for the
  authentication lifecycle.

### Deployment requirements (operator's responsibility)

These are **required**, not optional, for any non-local deployment:

1. Choose one explicit runtime posture:
   - **Scoped** (recommended): dedicated unprivileged service account
   - **Privileged** (maximum capability): root/system-level service on an isolated host
   In either posture, document and review the decision.
2. Bind the HTTP transport to loopback and place a TLS reverse proxy in
   front with an IP allowlist (reference `deploy/Caddyfile`).
3. Apply the systemd unit and hardening drop-in (`deploy/systemd/`).
4. Scope SSH credentials per role; prefer one key per scope, revocable
   independently. Do not reuse a single all-powerful key. Use
   `RELAY_SHELL_SSH_KNOWN_HOSTS=strict` with `RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false`
   in production.
5. Ship the audit log off-host and alert on gaps.
6. Keep the host patched; treat compromise of the MCP client or transport
   as equivalent to compromise of the service account.
7. If `RELAY_SHELL_POLICY_DENY` / `RELAY_SHELL_POLICY_ALLOW` are set (both are unanchored
   `re.search` patterns, and an `ALLOW` match admits the whole call, so anchor it),
   review the regex for catastrophic backtracking. The pattern is compiled
   with stdlib `re` (no timeout) and matched on every tool call on the
   asyncio event loop; a pathological pattern is a self-inflicted DoS.
   Prefer simple, anchored, atomic-group-free literals.

### Residual risk

If the MCP client or the transport is compromised, an attacker obtains the
capabilities of the service account on this host and any host its SSH
credentials reach. In privileged posture, this is effectively root-level host
control. Scope accounts/keys accordingly and isolate the host. This is stated
plainly so it can be designed around rather than discovered.

Sessions (`shell_spawn`, `ssh_spawn`) and port forwards are shared by all approved clients:
there is no per-client owner, so under multi-client OAuth any client can list, read, drive
and close the others' sessions (accepted 2026-10-14, A14-RS). Treat all approved clients as
one trust domain, or run one instance per domain.

An `ssh_config` that uses `ProxyCommand` or `Match exec` makes the server start a local
process (`Match exec` through a shell, at config evaluation) under the service account.
That is operator-written configuration, so it is trusted, but it is not audited per call and
carries no seccomp-notify observation; prefer `ProxyJump`.

OAuth operator approval gates a *client*, not each authorization: with the shipped edge
template `/authorize` is public and has no login step, so a host that knows an approved public
client's `client_id` can obtain a token. The edge CIDR gate keeps that token unusable outside
the allowlist, so a broad allowlist removes the protection. See the residual-risk subsection in
`docs/auth.md` ("Operator approval").

## Supported versions and response targets

The latest released pre-1.0 minor receives security patches; older minors are not
backported. Check releases and pyproject.toml for the current version.
Existing goals: acknowledge within 7 days; share a fix or mitigation plan within
30 days of triage. Coordinate public advisory and credit when the fix ships.

## Scope and resource admission

In scope: authentication/authorization or tier bypass, audit evasion, secret
leakage, transport defects and privilege gain beyond the documented posture.
Intended, authenticated, policy-permitted shell/SSH execution and the explicitly
unsandboxed service-account posture are not themselves vulnerabilities.
Relevant exploitable dependency issues remain in scope.

MCP inventory/ssh-config resource reads are audited but are not subject to tool
policy mode/deny admission. Restrict transport/client access when that metadata
must not be exposed. Verify resource and tool paths separately after changes.
