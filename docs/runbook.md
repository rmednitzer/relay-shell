# Maintenance Runbook

A working procedure for auditing, reviewing, enhancing, validating, and
extending `relay-shell`. Pair it with [`AGENTS.md`](../AGENTS.md) and
[`CLAUDE.md`](../CLAUDE.md): those define the operating contract, this is
the step-by-step playbook for executing against it.

Anything that touches the audit pipeline, the policy layer, redaction, or a
tool's externally observable response shape needs the full loop. Cosmetic
docs/README edits do not.

---

## 0. How to use this document

Each major section is a phase you can execute end-to-end on its own:

| Phase    | When to run                                          | Time budget |
|----------|------------------------------------------------------|-------------|
| Audit    | First contact, quarterly health check, post-incident | 60-90 min   |
| Review   | Every PR (yours or external)                         | 15-30 min   |
| Validate | Before every push                                    | 5-10 min    |
| Enhance  | Designated cleanup window                            | 1-3 hours   |
| Extend   | New tool / new transport / new posture               | 2-8 hours   |

The backlog at the end of the runbook is the queue. The `.md` update plan is
the inventory of what each documentation file should look like after the
next pass, so the next contributor (human or agent) knows what "done" means.

---

## 1. Orientation - the 10-minute flyover

Read these in this order and you have the whole system:

1. `README.md` - what the project is and why.
2. `SECURITY.md` - the threat model and the trust boundary.
3. `docs/architecture.md` - the request lifecycle diagram is the spine.
4. `docs/adr/0002-no-sandbox-full-access.md` - why no sandbox.
5. `docs/adr/0003-tiered-authority.md` - the policy layer.
6. `src/relay_shell/server.py` - every tool is wired here through one path.
7. `tests/test_stdio_e2e.py` - the end-to-end contract; one fixture, one
   real subprocess, one real tool call. If this passes the wiring is sound.

After that, look at any individual module via its dedicated test (e.g.
`redaction.py` <-> `tests/test_redaction.py`). Tests are the executable
spec.

---

## 2. Audit pass

Goal: confirm the system still behaves the way the docs and ADRs say it
does, and surface any drift.

### 2.1 Inventory

```bash
git ls-files | sort > /tmp/files.txt
wc -l src/relay_shell/*.py src/relay_shell/auth/*.py tests/*.py
```

Compare against the layout in `README.md` and the module table in
`docs/architecture.md`. Any new file that is not in either is undocumented
drift; fix the doc or remove the file.

### 2.2 Capability surface

```bash
# Every tool registered:
python -c "import asyncio; from relay_shell.config import Settings; \
  from relay_shell.server import build_server; \
  m = build_server(Settings(audit_path='/tmp/a.jsonl')); \
  print(*sorted(t.name for t in asyncio.run(m.list_tools())), sep='\n')"
```

Cross-check against:

- `docs/tools.md` (every tool documented, default tiers shown)
- `tests/test_server.py::_EXPECTED` (the contract test)
- The capability tables in `README.md`

All three sources must list the same set. Mismatches are the leading
indicator that someone added a tool without finishing the loop.

### 2.3 Audit-the-audit

The audit guarantee is "every tool call appended as one JSON line with hash
+ length, never body". Confirm it empirically by driving one real tool
through the audited runner and inspecting the resulting record:

```bash
AUDIT=/tmp/audit-check.jsonl
rm -f "$AUDIT"
python -c "
import asyncio
from relay_shell.config import Settings
from relay_shell.server import build_server
mcp = build_server(Settings(audit_path='$AUDIT'))
asyncio.run(mcp.call_tool('server_info', {}))
"
jq -c 'keys' "$AUDIT" | sort -u
```

Every record must contain `ts, tool, tier, denied, args, output_sha256,
output_len, exit_code` at minimum. `request_id` and `client_id` are
context-dependent and may be absent. Absence of any of the required
fields above is an audit regression.

Grep for the canonical "must never appear" markers:

```bash
# Output bodies must never reach the audit log. The stdio e2e test asserts
# this; this is a manual cross-check for the operator.
grep -F "body-42-only" "$AUDIT" && echo "FAIL: output body leaked into audit"
```

### 2.4 Policy posture

```bash
python -c "
from relay_shell.policy import Policy, classify, Tier
p_open = Policy('open')
p_ro   = Policy('readonly')
p_g    = Policy('guarded', allow=r'systemctl restart nginx')
for cmd in ['ls', 'rm -rf /tmp/x', 'systemctl restart nginx',
            'sudo apt-get install foo', 'shutdown -h now']:
    t = classify('shell_exec', cmd)
    print(f'{cmd!r:40} tier={int(t)} open={p_open.check(\"shell_exec\", cmd).allowed} '
          f'ro={p_ro.check(\"shell_exec\", cmd).allowed} '
          f'guarded={p_g.check(\"shell_exec\", cmd).allowed}')
"
```

Sanity-check that every Tier 2+ example is denied under `guarded` (unless
allowlisted - `guarded` refuses both `STATEFUL` (2) and `IRREVERSIBLE`
(3)), that `readonly` permits only Tier 0, and that the deny list fires
in `open`.

### 2.5 Secret redaction

```bash
python -c "
from relay_shell.redaction import redact
samples = [
  'Authorization: Bearer abcdef123456',
  'curl -H \"Authorization: Bearer eyJabc.def\" https://api/...',
  'mysql -uroot -pleaked-pw -h db',
  'ssh -p22 user@host',                       # MUST NOT redact -p22
  'export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789',
  '--password \"top secret pass\" --host db',
  '-----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\n-----END OPENSSH PRIVATE KEY-----',
]
for s in samples: print(redact(s))
"
```

Compare with the assertions in `tests/test_redaction.py`. If a new common
secret shape appears in real audit logs without redaction, that's a bug
report against `redaction.py`, not a deployment problem.

### 2.6 Resource bounds and timeouts

`server_info` reports the effective limits; check them against the deployed
posture (single-owner lab vs production):

```bash
RELAY_SHELL_AUDIT_PATH=/tmp/a.jsonl \
RELAY_SHELL_SSH_CONFIG=/tmp/no \
RELAY_SHELL_MAX_TIMEOUT=900 \
RELAY_SHELL_MAX_OUTPUT_HARD=1048576 \
RELAY_SHELL_MAX_SESSIONS=64 \
python -c "
import asyncio
from relay_shell.config import Settings
from relay_shell.server import build_server
mcp = build_server(Settings(audit_path='/tmp/a.jsonl'))
# Call the live server_info tool and print its JSON response so the
# bounds reported here include any runtime overrides, not just Settings.
content, _ = asyncio.run(mcp.call_tool('server_info', {}))
for block in content:
    if getattr(block, 'type', '') == 'text':
        print(block.text)
"
```

If any bound is wider than the ADR-blessed defaults, document the reason in
a deployment-specific note (the operator's env file is the right place, not
the code).

### 2.7 SSH posture

```bash
# Inventory + known-hosts mode actually resolved on this host:
RELAY_SHELL_AUDIT_PATH=/tmp/a.jsonl python -c "
from relay_shell.config import get_settings
from relay_shell.inventory import Inventory
s = get_settings()
inv = Inventory(s.ssh_config, s.inventory).load()
for h in inv.hosts(): print(h.as_dict())
print('default known_hosts mode:', s.ssh_known_hosts)
"
```

For production: `ssh_known_hosts` should be `strict`. `accept-new` is fine
for dev. `ignore` outside tests is a finding.

### 2.8 Edge / OAuth (HTTP transport only)

If a host actually serves the HTTP transport, run from outside the CIDR
allowlist and confirm 403:

```bash
curl -sk -o /dev/null -w "%{http_code}\n" "https://${RELAY_SHELL_EDGE_DOMAIN}/"
# Expected: 403 (CIDR-blocked) from any IP not in RELAY_SHELL_EDGE_CLIENT_CIDRS.
curl -sk -I "https://${RELAY_SHELL_EDGE_DOMAIN}/.well-known/oauth-protected-resource"
# Expected: 200 (discovery is always reachable, by design).
```

`scripts/healthcheck.sh` covers the local liveness probe. A non-zero exit is
an alertable condition; any HTTP response (including 401/403/404) means the
listener is up.

### 2.9 Audit-log hygiene

On a real deployment:

```bash
# Append-only attribute set?
lsattr /var/log/relay-shell/audit.jsonl | head -1
# Logrotate config installed and recognized?
sudo logrotate -d /etc/logrotate.d/relay-shell 2>&1 | head -30
# Off-host shipping running?  (deployment-specific; not in-tree)
```

A degraded audit (e.g. permission-denied on the path) is reported in
`server_info().audit.degraded`. That flag flipping to `true` in production
is page-worthy.

---

## 3. Review pass

Use this for every PR, your own or external.

### 3.1 Pre-review checklist

- [ ] CI is green on the PR head commit (lint, type-check, tests, CodeQL,
      dependency-review).
- [ ] No new file is undocumented in `docs/architecture.md` module table.
- [ ] No new tool is missing from `docs/tools.md`,
      `tests/test_server.py::_EXPECTED`, and the README capability tables.
- [ ] No new env var is missing from `.env.example`, `Settings`, and
      `docs/deployment.md`.
- [ ] No new dependency is added without a justification in the PR body and
      a pinned version in `requirements.txt`.

### 3.2 Per-module focus areas

| Module               | First thing to check                                                                              |
|----------------------|---------------------------------------------------------------------------------------------------|
| `server.py`          | Every new tool goes through `Relay.run()`. No tool ever raises into the transport.                |
| `patterns.py`        | The single home for `TIER2_PATTERN` / `TIER3_PATTERN` / `PRIV_ESC_PATTERN` and the redaction tables. Any change bumps `PATTERNS_VERSION`. Paired tests in `tests/test_patterns.py`. |
| `policy.py`          | Consumes `patterns`; deny list is still the first gate; `_READ_ONLY_TOOLS` / `_MUTATING_TOOLS` membership intact. |
| `audit.py`           | Output body never written, only `sha256` + `len`. `degraded` path still degrades, not crashes.    |
| `redaction.py`       | Consumes `patterns`; the loop order (URL creds → prefix patterns → whole-match patterns → MySQL family) is unchanged. |
| `sessions.py`        | Lost-wakeup invariant: `recv` clears the event under the buffer lock before awaiting.             |
| `sshpool.py`         | `known_hosts` arg is validated. Connection cache keyed by `user@host:port`. Forwards leak-free.   |
| `auth/oauth.py`      | File modes (0o700 dir / 0o600 files), atomic save, lazy expiry, single-client lockdown intact.    |
| `shelltools.py`      | `start_new_session=True` preserved (so `killpg` works). Env overlay does not propagate JSON errors. |
| `inventory.py`       | Wildcard `Host *` patterns are skipped in the flat listing. `resolve()` passthrough behavior holds. |

### 3.3 Security-sensitive diffs

Trigger an extra review pass if the diff touches:

- `patterns.py`, `audit.py`, `redaction.py`, `policy.py`
- The `Relay.run()` body in `server.py`
- `auth/oauth.py` (any TTL, store, or token-shape change)
- `deploy/install*.sh` (anything that writes a systemd unit / EnvironmentFile)
- `deploy/Caddyfile` (CIDR matcher or header changes)

If you are reviewing through Claude Code, the bundled `/security-review`
skill scans the current diff and surfaces common findings in one pass;
that is the lowest-friction option. Without it, walk the diff against
this manual checklist:

- audit-record fields unchanged (`ts, tool, tier, denied, args,
  output_sha256, output_len, exit_code`), output body still hashed only;
- `policy_text` passed to `Relay.run()` covers every byte the executor
  will see (command + stdin + env_json + script body);
- redaction patterns have paired over-scrub / under-scrub tests;
- `O_APPEND | O_CREAT` preserved in `audit.AuditLogger.__init__`;
- OAuth store files still written with `0o600` and the state dir with
  `0o700` regardless of umask;
- `deploy/install-edge.sh` still refuses to clobber an unmanaged
  `/etc/caddy/Caddyfile` without `RELAY_SHELL_EDGE_FORCE=1`;
- `deploy/Caddyfile` security headers (HSTS, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy) and the CIDR `@blocked` matcher
  still present.

### 3.4 Common review failures (seen in past PRs)

These keep coming back; check them explicitly:

1. **New tool added but `tests/test_server.py::_EXPECTED` not updated** -
   the count assertion catches it but the message is confusing if the test
   maintainer forgot to bump `len(names) == 18`.
2. **Redaction pattern that eats the next argv token** - quoted/escaped
   values are tested; if you change `REDACTION_PREFIX_PATTERNS` in
   `patterns.py`, run `tests/test_redaction.py` and
   `tests/test_patterns.py` and re-read every existing assertion.
3. **Policy text not including stdin/env in `shell_exec`** - regression
   path: the deny list must see the same text the executor sees. The
   `policy_text` argument to `Relay.run()` is the contract.
4. **`O_APPEND | O_CREAT` collapsed to plain `open()`** - breaks
   `chattr +a` audit files. Test `test_audit_precreate_uses_o_append`
   guards this; do not remove it.
5. **Caddy validator failing silently** - `install-edge.sh` runs
   `caddy validate`; if you change the Caddyfile, dry-run the installer.

---

## 4. Validate (the quality gates)

### 4.1 Local loop (the canonical sequence)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

ruff check .
ruff format --check .
mypy
pytest -q
```

A green local loop is the bar before pushing. Anything that fails CI but
not locally is a CI-config bug; fix that, not the test.

### 4.2 Targeted runs

```bash
# A single module's tests:
pytest -q tests/test_redaction.py

# Only the SSH integration suite (in-process asyncssh server):
pytest -q tests/test_ssh_integration.py

# Only the end-to-end stdio test (real subprocess + real MCP client):
pytest -q tests/test_stdio_e2e.py

# Force serial + verbose (for hangs):
pytest -x -vv -s
```

`pytest-asyncio` mode is `auto` (see `pyproject.toml`); you do not need to
mark coroutines.

### 4.3 Coverage (CI floor: 75%, current ~78%)

`coverage` is in the dev extra and runs as part of the CI loop with a
75% floor that fails the workflow on regression. Reproduce locally:

```bash
# One-time: wire subprocess coverage so the stdio e2e contributes.
python -c "import site, pathlib; \
  pathlib.Path(site.getsitepackages()[0], 'coverage_subprocess.pth') \
    .write_text('import coverage; coverage.process_startup()\n')"

export COVERAGE_PROCESS_START=$(pwd)/pyproject.toml
coverage erase
coverage run -m pytest -q
coverage combine
coverage report           # uses fail_under=85 from [tool.coverage.report]
coverage html && xdg-open htmlcov/index.html
```

Why the `.pth` dance: the `test_stdio_e2e.py` fixture launches
`python -m relay_shell` as a subprocess and speaks MCP over its stdio.
Without subprocess collection, `server.py`'s `@mcp.tool()` wrappers
register as uncovered even though they run on every e2e tool call.
The `.pth` file calls `coverage.process_startup()` at every
interpreter start; `COVERAGE_PROCESS_START` gates the actual recording
to runs that opt in.

Modules to bring to and hold above 90%: `policy.py`, `redaction.py`,
`audit.py`, `sessions.py`. Anything that handles secrets or admission.
Lifting the project floor to 85% means hardening `sshpool.py` (65%),
`server.py` wrapper bodies (53%), and `sessions.py` (79%) - tracked as
a follow-up in §7.2.

### 4.4 Type-checking notes

`mypy` is **strict** for the package and relaxed only for `relay_shell.server`
(FastMCP's `Context` typing varies by SDK minor version) and the `asyncssh`
module (no stubs). When upgrading `mcp`:

1. Run `mypy` first.
2. If FastMCP's tool decorator typing changed, prefer narrowing the
   override in `pyproject.toml` over `# type: ignore` in the file.
3. If `asyncssh` ever ships stubs, drop the `ignore_missing_imports`
   override and re-run.

### 4.5 Manual smoke (stdio)

```bash
# Inspector-style check:
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}' \
  | python -m relay_shell
```

Easier: run `pytest tests/test_stdio_e2e.py -v` - it does exactly this and
asserts on the response.

### 4.6 Manual smoke (HTTP)

```bash
RELAY_SHELL_TRANSPORT=http RELAY_SHELL_AUDIT_PATH=/tmp/a.jsonl \
  python -m relay_shell &
SERVER_PID=$!
sleep 1
scripts/healthcheck.sh
curl -s http://127.0.0.1:8080/.well-known/oauth-protected-resource \
  | jq .   # only meaningful if RELAY_SHELL_AUTH_ENABLED=true
kill $SERVER_PID
```

### 4.7 The release gate

Before tagging a release:

- [ ] `CHANGELOG.md` `[Unreleased]` section moved under the version + date.
- [ ] `pyproject.toml` `version` bumped and matches `__init__.__version__`.
- [ ] Full local loop green on a clean checkout.
- [ ] `pip install build && python -m build` produces a wheel + sdist that
      installs cleanly into a fresh venv and exposes the `relay-shell` CLI.
- [ ] ADRs that informed the release are linked from the changelog entry.
- [ ] `git tag -s vX.Y.Z` (signed) and `git push --tags`.

When the tag lands, `.github/workflows/sbom.yml` generates a CycloneDX
SBOM (JSON + XML, CDX spec 1.5) for the resolved environment and
attaches both files to the GitHub release. PyPI publish automation
(B-005) is still open; tag-driven trusted publishing will land once
the PyPI trusted-publisher claim is configured on the project side.

---

## 5. Enhance (consolidation and cleanup)

Discrete, low-risk improvements you can ship without changing the public
surface. The intent is to leave the next contributor a smaller surface area
and clearer code, not to land a refactor for its own sake.

### 5.1 Consolidation candidates

- **C-001 Connection-cache TTL.** `SshPool._conns` has no idle eviction.
  Long-running deployments accumulate connections to hosts they will not
  contact again. Add an idle reaper or a max-cache-size LRU; mirror the
  shape of `SessionRegistry._sweep` for consistency.
- **C-002 Single source of truth for the tool list.** Today the set lives
  in `server.py` (definitions), `tests/test_server.py::_EXPECTED`
  (contract), `docs/tools.md` (docs), and the README capability tables.
  Either generate the docs and the test set from a list module, or accept
  the duplication and add a CI check that the four are equal.
- **C-003 Unify `connect_kwargs` plumbing.** Every SSH tool builds the
  same dict in `server.py` via `Relay.connect_kwargs`. Move the optional
  `connect_timeout` overlay into the same helper so the
  `ssh_check`-internal extension is not a special case.
- **C-004 `_INSTRUCTIONS` lives next to the tool list.** The constant at
  the bottom of `server.py` lists tools by hand. Generate it from the
  registered tool names so it can never drift.
- **C-005 `Inventory` field naming.** `Settings.ssh_config` (config path)
  is passed into `Inventory(ssh_config_path=...)` and surfaces as
  `ssh_config_file` on the same object. Settle on one name across the
  three sites.

### 5.2 Refactor candidates

- **R-001 Extract a `ToolDef` table.** `server.py` is ~720 lines of mostly
  identical `@mcp.tool()` wrappers. A small table-driven registration
  (tool name, default tier override, work function, audit-args extractor)
  would cut the file in half and make adding a tool a one-line change.
  Risky if rushed - keep one PR per row migrated.
- **R-002 `policy_text` builder.** Each tool inlines its own `policy_text`
  string. Extract per-tool helpers (`_policy_text_shell_exec`, etc.) so
  the contract "everything the executor sees, the policy sees" is one
  function per tool and easy to grep.
- **R-003 Session backend factory.** `LocalPtyTransport.spawn` and
  `SshPool.open_process` both return a `Transport`. A tiny factory module
  would let `shell_spawn` / `ssh_spawn` share the registry-add code path
  exactly.
- **R-004 OAuth store backend interface.** `_Store` is hard-coded to JSON
  files. Promote it to a `Protocol` so an operator could plug in a
  Redis-backed store without touching `FileOAuthProvider`. Only worth
  doing if a second store is genuinely on the roadmap.

### 5.3 Tests to add (gap analysis)

- **T-002** `server_info` is exercised via the stdio e2e test, but not by
  itself. A direct unit test confirming every documented field is present
  would catch silent removals.
- **T-003** No test asserts the `session_recv` "ended" message shape. The
  registry produces `[session ... ended, exit=N]`; a regex test would
  freeze that contract.
- **T-004** No test covers `ssh_forward` close on connection drop. Add a
  fixture variant that closes the SSH server mid-forward.
- **T-005** No property-based test for `truncate` (UTF-8 boundary safety
  on arbitrary input). One `hypothesis` strategy would harden it.
- **T-006** `redaction.redact` has no fuzz harness. A small
  `hypothesis` test that constructs random argv strings around known
  secret patterns would catch the over-scrub / under-scrub failure mode
  that keeps appearing in PR review.

---

## 6. Extend (recipes for new capability)

Anything in this section that adds a new transport, auth provider,
policy category, or changes the audit-record shape needs an ADR
under `docs/adr/` before code lands. The
[ADR index](adr/README.md) documents the criteria and the next free
number.

### 6.1 Add a new tool

1. Decide the tier. If it can mutate local or remote state, it is at least
   Tier 1. If the failure mode is hard to roll back, Tier 3.
2. Pick the right module:
   - Local one-shot -> add a helper in `shelltools.py`.
   - SSH-bound -> extend `sshpool.py`.
   - PTY-bound -> extend `sessions.py` (rarely needed; the session API is
     transport-agnostic).
3. Register the tool in `server.py` as `@mcp.tool()`. The wrapper must:
   - clamp its timeout/output budget via `app.clamp_timeout` / `app.clamp_output`;
   - call `app.run(...)` with `policy_text` covering **every** byte the
     executor will see (command + stdin + env_json + script body);
   - return only through `app.run`, never raise.
4. Update, in the same PR:
   - `tests/test_server.py::_EXPECTED` (and the `len()` assertion).
   - `docs/tools.md` table with the default tier and parameters.
   - README capability tables.
   - `_INSTRUCTIONS` string at the bottom of `server.py`.
5. Add tests:
   - Unit test of the underlying helper (in `tests/test_shell.py`,
     `tests/test_ssh_integration.py`, or a new module).
   - A wiring test that calls the tool through the FastMCP instance and
     asserts the audit record is correct.

### 6.2 Add a new transport

FastMCP today supports `stdio` and `streamable-http`. Adding a third
(e.g. a unix socket transport) means:

1. Validate value in `Settings._v_transport` and `_TRANSPORTS`.
2. Branch in `__main__.main()` on `settings.transport`.
3. Document it in `.env.example`, `docs/deployment.md`,
   `docs/architecture.md`, and `docs/adr/0001-runtime-and-sdk.md`
   (Consequences section).
4. Add an e2e test analogous to `test_stdio_e2e.py`.

### 6.3 Add a new auth provider

`FileOAuthProvider` is the only provider today and is constructed only when
`auth_enabled=true` and `transport=http`. To add another (e.g. a
JWT-static-keys provider for service-to-service):

1. Implement the `OAuthAuthorizationServerProvider` contract under
   `src/relay_shell/auth/<name>.py`.
2. Export it from `auth/__init__.py`.
3. Add a settings field (e.g. `auth_provider: str = "file"`) and switch
   on it in `server.build_server()` where `make_oauth_provider` is called.
4. Write an offline test that exercises the full token lifecycle, as
   `tests/test_oauth.py` does for the file provider.
5. Write an ADR documenting the trade-off (file simplicity vs the new
   provider's complexity).

### 6.4 Add a new policy heuristic

Anything you add to `TIER2_PATTERN` / `TIER3_PATTERN` / `PRIV_ESC_PATTERN`:

1. Edit `src/relay_shell/patterns.py` (the single source). Bump
   `PATTERNS_VERSION` if the addition changes classification semantics.
2. Add a paired test in `tests/test_patterns.py`: one *positive* case
   (classifies as expected) and one *negative* near-miss case
   (`\b`-bounded text that does not over-match).
3. Document the addition in `docs/adr/0003-tiered-authority.md` if the
   heuristic represents a new category (not just another verb).
4. Never replaces the deny list as a security control. The heuristics
   are advisory in `open` mode; the deny list is the only guarantee.

### 6.5 Add a new redaction rule

1. Edit `src/relay_shell/patterns.py`. Choose between
   `REDACTION_PREFIX_PATTERNS` (keeps the non-secret prefix) and
   `REDACTION_PATTERNS` (collapses the whole match). Prefix-preserving
   is almost always the right choice for audit usefulness. Bump
   `PATTERNS_VERSION`.
2. Anchor on structure (PEM markers, `Bearer `, `--password `, URL
   `://user:pass@`) rather than on the secret's character class - the
   character class evolves, the structure does not.
3. Add the over-scrub and under-scrub test as a pair in
   `tests/test_patterns.py` (or `tests/test_redaction.py` for higher-
   level scenarios). The `test_redact_cli_flag_does_not_eat_next_flag`
   family is the model.

---

## 7. Backlog

Prioritized. "P0" = blocking the next release. "P1" = should land in the
next milestone. "P2" = good-to-have, not blocking. "P3" = nice idea, no
commitment.

### 7.1 Capability

(Items in this category are tracked here as they land; the queue is
currently empty.)

### 7.2 Quality + automation

- **B-005 (P1)** Add a `release.yml` workflow that on a `v*` tag builds
  the wheel/sdist, runs the full test suite, and publishes to PyPI via
  trusted publishing (OIDC, no long-lived token). Gate on tag signature.
- **B-010 (P3)** Add a `hypothesis`-based fuzz suite for `redact` and
  `classify`; run nightly only (separate workflow with `schedule:`).
- **B-022 (P3)** Raise the CI coverage floor from 85% (current) to 90%.
  After `tests/test_tool_wrappers.py` lifted `server.py` to 95% and
  overall to ~88%, the remaining gap is `sshpool.py` (~68%; SSH
  non-happy paths, forwarding error handling). One PR adding fault
  injection around the asyncssh dispatcher would close most of it;
  treat it as security-sensitive because those error paths are what
  the operator sees when a remote host misbehaves.

### 7.3 Operations + observability

- **B-014 (P3)** Add an `RELAY_SHELL_AUDIT_FORMAT=jsonl|cef|leef` knob for
  operators whose SIEMs only accept CEF/LEEF. Default stays JSONL.

### 7.4 Docs and contribution

(Items in this category are tracked here as they land; the queue is
currently empty.)

### 7.5 Security hardening (incremental, no posture change)

- **B-021 (P3)** Investigate `seccomp-bpf` notification mode (not
  enforcement) for the local executor: not a sandbox, but an additional
  audit channel covering syscalls. ADR-worthy before any code lands.

---

## 8. `.md` update run (per-file)

A single-pass cleanup of every Markdown file in the tree. Each entry below
lists what to add, what to keep, and what to remove. The intent is one PR
per file (or one PR for the whole batch if no behavior changes), reviewed
by the same checklist.

### 8.1 `README.md`

- Keep: title, DeepWiki badge, Why, Capabilities tables, Quickstart,
  Security posture summary, Layout, Development, License.
- Add:
  - A short "Status" line under the title: current version, supported
    Python, supported transports.
  - A "Compatibility matrix" block (tested on Ubuntu 24.04 + Python 3.12;
    macOS dev OK but unsupported; Windows out of scope).
  - A link to the new `docs/runbook.md` under "AI contributor guidance".
- Remove: nothing.
- Cross-checks: capability tables must match `docs/tools.md` and
  `tests/test_server.py::_EXPECTED`.

### 8.2 `SECURITY.md`

- Keep: Model, Trust boundary, Deployment requirements, Residual risk,
  Reporting, Scope sections - they are accurate and pithy.
- Add:
  - A "Disclosure timeline" subsection under "Reporting a vulnerability"
    (acknowledge in 7 days, fix or mitigation plan in 30, public
    advisory + credit when shipped).
  - A "Supported versions" table once the project tags a second release
    (today only 0.1.0 exists). Until then, omit rather than fake.
- Remove: nothing.

### 8.3 `CHANGELOG.md`

- Keep: Keep-a-Changelog format and the `[Unreleased]` section structure.
- Add (now, as part of this runbook PR):
  - An entry under `[Unreleased] / Added`: "Maintenance runbook at
    `docs/runbook.md` covering audit/review/validate/enhance/extend
    procedures and the working backlog."
- Update on every release: cut the `[Unreleased]` block, stamp the
  version + date, link diffs.

### 8.4 `AGENTS.md`

- Keep: Mission, Non-negotiables, References, Implementation standards,
  Change workflow, Repo map, Definition of done.
- Add:
  - A line in section 5 pointing at `docs/runbook.md` as the executable
    procedure for sections 1, 4, and 6.
  - A line in section 6 noting that the canonical tool list lives in
    `tests/test_server.py::_EXPECTED` (until C-002 collapses the four
    duplicated sources into one).
- Remove: nothing.

### 8.5 `CLAUDE.md`

- Keep: Objective, Core behavior expectations, Required development loop,
  Coding guidance, GitHub optimization checklist, Trusted references.
- Add:
  - Under "Required development loop", a note: "Step 1 is `docs/runbook.md`
    section 2 (Audit) for any change touching `policy`, `redaction`,
    `audit`, or the `Relay.run()` body."
  - Under "When uncertain", a fifth bullet: "Prefer extending the
    backlog in `docs/runbook.md` over inventing scope mid-PR."
- Remove: nothing.

### 8.6 `docs/architecture.md`

- Keep: the diagram, request-lifecycle prose, module table, concurrency
  notes, transport notes, security-model link.
- Add:
  - A short "Where this maps in code" appendix linking each lifecycle
    step (1-5 in section "Request lifecycle") to the exact function in
    `server.py` (`_ctx_ids`, `policy.check`, `redact_args`, `truncate`,
    `audit.record`).
  - A pointer to `docs/runbook.md` section 2 for the operator-facing
    audit of these guarantees.
- Remove: nothing.

### 8.7 `docs/tools.md`

- Keep: the per-tool tables, the conventions header, the interactive
  pattern example, the error grammar.
- Add:
  - A note under each tool's row stating which test exercises it (single
    file path, no line numbers - lines drift). Helps reviewers find the
    contract.
  - A "Tier reference" sidebar with the four-line tier definition so the
    table is self-contained.
- Remove: nothing.
- Cross-checks: the set of tools listed here must equal
  `tests/test_server.py::_EXPECTED`. The default-tier note for each tool
  must match `policy._READ_ONLY_TOOLS` / `policy._MUTATING_TOOLS` / the
  `classify` function.

### 8.8 `docs/deployment.md`

- Keep: every section. The deployment guide is accurate and
  worked-example heavy.
- Add:
  - A "Pre-flight checklist" at the top (service account exists, audit
    dir owned by the account, append-only attribute settable on the FS,
    DNS resolves for the edge domain, port 80/443 reachable).
  - A "Backup and restore" subsection (clients.json/tokens.json under
    the OAuth state dir, the audit log itself, the systemd EnvironmentFile).
  - Link to `docs/runbook.md` section 4.6 for the manual HTTP smoke.
- Remove: nothing.

### 8.9 `docs/adr/0001-runtime-and-sdk.md`

- Keep: as is. The pin and the rejection of alternatives are still valid.
- Add: nothing now. When `mcp` is next bumped, add a one-line Consequences
  entry stating the pin moved and the test suite was used to validate it.

### 8.10 `docs/adr/0002-no-sandbox-full-access.md`

- Keep: as is. The posture has not changed.
- Add: nothing.

### 8.11 `docs/adr/0003-tiered-authority.md`

- Keep: as is.
- Add: nothing now. Update if `TIER2_PATTERN` / `TIER3_PATTERN` (in
  `src/relay_shell/patterns.py`) gain a new *category* (not just
  another verb) - new entries are heuristic improvements, not policy
  changes.

### 8.12 `docs/adr/0004-edge-tls-automation.md`

- Keep: as is. It accurately reflects what `install-edge.sh` does today.
- Add:
  - A short "Operational notes" appendix listing the `journalctl -u caddy`
    invocation for cert issuance troubleshooting and the
    `caddy validate --config /etc/caddy/Caddyfile` invocation for
    drift detection.

### 8.13 `NOTICE`

- Keep: as is.
- Add: nothing.

### 8.14 New `.md` files to create (tracked by the backlog)

(The queue is currently empty. New entries are added here when a
backlog item references a not-yet-created file so the maintenance
plan lands in the same PR.)

### 8.15 `CONTRIBUTING.md`

- Keep: scope (what changes we accept), branch naming, the local-loop
  recipe, the documentation-moves-with-code table, the
  security-sensitive-PR section, the architecturally-significant
  paragraph, and the license note.
- Add: an entry to the docs-moves-with-code table whenever a new
  cross-reference becomes routine (e.g. a new "if you change X" row).
- Cross-checks: the local-loop recipe must match section 4.1 of this
  runbook. If section 3.1 or 3.3 changes, update `CONTRIBUTING.md` and
  `.github/PULL_REQUEST_TEMPLATE.md` together.

### 8.16 `.github/PULL_REQUEST_TEMPLATE.md` and `.github/ISSUE_TEMPLATE/*.md`

- Keep: the section 3.1 cross-reference checklist in the PR template,
  and the security-sensitive-diff confirmations from section 3.3. Both
  the bug and the security issue templates point to `SECURITY.md` for
  the disclosure process so the trust-boundary text has one home.
- Add: a row to the PR-template "type of change" list whenever a new
  category of change becomes routine (e.g. new transport, new auth
  provider) - keep the list short or it stops being read.
- Cross-checks: if section 3.1 or 3.3 of this runbook changes, mirror
  the change in `.github/PULL_REQUEST_TEMPLATE.md`.

### 8.17 `docs/audit-shipper.md`

- Keep: the three worked examples (Vector, Fluent Bit, journal-remote),
  the §0 "common requirements" preamble (append-only preserved, no
  re-encoding, rotation-safe, observable, TLS to remote), and the
  picking-one matrix at the end.
- Add: a fourth recipe only when a fourth deployment shape is in
  production and demonstrably different (e.g. an S3 object-lock sink
  with an event-driven Lambda processor). Resist adding shapes that
  reduce to "configure your aggregator's file input"; the three here
  cover the structural choices.
- Cross-checks: every example must still preserve the rotation
  posture documented in `deploy/logrotate/relay-shell` and the
  append-only attribute documented in `docs/deployment.md` §6. If
  either of those changes, the recipes here change with them.

### 8.18 `docs/adr/README.md`

- Keep: the status-vocabulary table, the indexed ADR list (number /
  title / status / date / one-line subject), the "when to write an
  ADR" criteria, the next-free-number marker, and the cross-references
  to `docs/architecture.md` and `docs/runbook.md` §6.
- Add: a row to the index table whenever a new ADR lands. Update the
  status column when an ADR is superseded or deprecated.
- Cross-checks: the index must list every file in `docs/adr/000*.md`;
  any superseded ADR must carry a `Superseded by` line in its own
  header so the chain is navigable from either direction.

### 8.19 `CODE_OF_CONDUCT.md`

- Keep: the upstream pointer to the canonical Contributor Covenant 2.1
  URL (so wording changes track upstream automatically), the scope
  paragraph, the enforcement-reporting channel (private GitHub
  security advisory, same as vulnerability reports), and the
  Community Impact Guidelines link.
- Add: nothing. If the project ever moves to a different code-of-
  conduct framework, replace the upstream pointer; do not maintain a
  fork of the Contributor Covenant text in-tree.
- Cross-checks: `README.md` and `CONTRIBUTING.md` both link to this
  file; if its path changes, update both. The enforcement-reporting
  channel must match `SECURITY.md`'s reporting channel so reporters
  have a single trust path to remember.

---

## 9. Appendix - useful one-liners

```bash
# Full local quality gate, exit non-zero on any failure:
ruff check . && ruff format --check . && mypy && pytest -q

# Tool list as registered, sorted:
python -c "import asyncio; from relay_shell.config import Settings; \
  from relay_shell.server import build_server; \
  m = build_server(Settings(audit_path='/tmp/a.jsonl')); \
  print(*sorted(t.name for t in asyncio.run(m.list_tools())), sep='\n')"

# Audit-record schema (keys present in the first record of a JSONL file):
jq -c 'keys' /var/log/relay-shell/audit.jsonl | head -1

# Effective settings as parsed (run with the same env the service uses):
python -c "from relay_shell.config import get_settings; \
  import json; print(json.dumps(get_settings().model_dump(), indent=2))"

# Show every tool's audited args shape on a dry run:
grep -nE '"(args|tool)":' /var/log/relay-shell/audit.jsonl | head -20

# Validate the Caddyfile in place (requires Caddy installed):
RELAY_SHELL_EDGE_DOMAIN=example.test RELAY_SHELL_EDGE_ACME_EMAIL=x@x \
  caddy validate --config deploy/Caddyfile --adapter caddyfile

# Re-render the parameterized Caddyfile (dry run, no install):
RELAY_SHELL_EDGE_DOMAIN=example.test RELAY_SHELL_EDGE_ACME_EMAIL=x@x \
  RELAY_SHELL_EDGE_DRY_RUN=1 sudo -E deploy/install-edge.sh
```
