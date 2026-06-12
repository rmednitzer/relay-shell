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

If the deployment runs with `RELAY_SHELL_AUDIT_CHAIN=true`
([ADR 0007](adr/0007-audit-hash-chain.md)), also verify the tamper-evident
chain — on the live log and on a shipped-off-host copy:

```bash
relay-shell --verify-audit --json
# fail-closed: exit 0 only for a clean, genesis-anchored chain. exit 2 for a
# missing/empty log, a record edited / reordered / inserted / deleted from the
# interior, or a non-genesis start (head-truncation). Pass --segment to verify
# a mid-stream rotation segment. server_info reports whether the chain is even
# on:  .audit.chain == true  and  .audit.format == "jsonl"
```

A `FAILED` result is page-worthy: a missing/empty audit log, or an on-disk
stream that diverged from what the relay emitted (`broken_at` localizes a
break). Note the bounds of single-file verification: it does not detect
**tail-truncation** (dropping the newest records leaves a valid prefix) —
catch that by comparing the latest `seq` against the off-host copy, which has
the later records. The default is strict (a non-genesis start fails as possible
head-truncation); pass `--segment` only when verifying a mid-stream rotation
segment that legitimately starts at `seq > 0`.

If the deployment runs with `RELAY_SHELL_SECCOMP_NOTIFY=true`
([ADR 0006](adr/0006-seccomp-notify-audit-channel.md)), confirm the
syscall-notify channel actually engaged — an enabled-but-inactive channel is a
silent audit gap on the child side. `server_info.seccomp.supported` must be
`true` (a `false` carries a `reason`, most often "requires CAP_SYS_ADMIN"), and
one real `shell_exec` should leave at least one `syscall_notify` line behind:

```bash
jq -r 'select(.tool=="syscall_notify") | .syscall' "$AUDIT" | sort -u
# expect at least: execve
```

Treat `supported=false` while the env var is on as a finding: grant
`CAP_SYS_ADMIN` (the channel installs without `no_new_privs`, so set-uid/`sudo`
is unaffected) or accept the child-side gap explicitly.

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
# Provider-token samples are assembled from prefix + body at runtime so this
# runbook never ships a contiguous secret-shaped literal (same reason
# tests/test_patterns.py uses _synth); redact() still sees the joined value.
samples = [
  'Authorization: Bearer abcdef123456',
  'curl -H \"Authorization: Bearer eyJabc.def\" https://api/...',
  'mysql -uroot -pleaked-pw -h db',
  'ssh -p22 user@host',                       # MUST NOT redact -p22
  'export GITHUB_TOKEN=' + 'ghp_' + 'abcdefghijklmnopqrstuvwxyz0123456789',
  '--password \"top secret pass\" --host db',
  '-----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\n-----END OPENSSH PRIVATE KEY-----',
  # Bare provider tokens (no --flag / Bearer prefix) — must still redact:
  '{\"k\": \"' + 'AIza' + 'SyD-1234567890abcdefghijklmnopqrstuv\"}',  # Google API key
  'export NPM_TOKEN=' + 'npm_' + 'abcdefghijklmnopqrstuvwxyz0123456789',  # npm token
  'id_token=' + 'eyJhbGciOiJIUzI1NiJ9.' + 'eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N',  # JWT
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
      dependency-review, pip-audit, gitleaks).
- [ ] No new file is undocumented in `docs/architecture.md` module table.
- [ ] No new tool is missing from `docs/tools.md`,
      `tests/test_server.py::_EXPECTED`, and the README capability tables.
- [ ] No new MCP resource is missing from `docs/tools.md` §Resources,
      the README Resources subsection, and the audit-tool-name table in
      both places (resource reads are audited; the `tool` field must stay
      stable to keep cardinality bounded and to let redaction run on
      user-controlled parts).
- [ ] No new env var is missing from `.env.example`, `Settings`, and
      `docs/deployment.md`.
- [ ] No new dependency is added without a justification in the PR body and
      a pinned version in `requirements.txt`.
- [ ] No new metric is undocumented in `docs/deployment.md` §9a and the
      README diagnostics paragraph (HTTP transport adds metric blocks
      to the `/metrics` exposition).

### 3.2 Per-module focus areas

| Module               | First thing to check                                                                              |
|----------------------|---------------------------------------------------------------------------------------------------|
| `server.py`          | Every new tool goes through `Relay.run()`. No tool ever raises into the transport.                |
| `patterns.py`        | The single home for `TIER2_PATTERN` / `TIER3_PATTERN` / `PRIV_ESC_PATTERN` and the redaction tables. Any change bumps `PATTERNS_VERSION`. Paired tests in `tests/test_patterns.py`. |
| `policy.py`          | Consumes `patterns`; deny list is still the first gate; `_READ_ONLY_TOOLS` / `_MUTATING_TOOLS` membership intact. |
| `audit.py`           | Output body never written, only `sha256` + `len`. `degraded` path still degrades, not crashes. With `audit_chain` on, `seq`/`prev`/`chain` are appended under `_chain_lock` and `verify_chain` round-trips (ADR 0007); the default-off path is byte-identical. |
| `redaction.py`       | Consumes `patterns`; the loop order (URL creds → prefix patterns → whole-match patterns → MySQL family) is unchanged. |
| `sessions.py`        | Lost-wakeup invariant: `recv` clears the event under the buffer lock before awaiting. PTY spawn adopts the active seccomp monitor; the transport stops it in `aclose()` — on the failure path too (B-026). |
| `sshpool.py`         | `known_hosts` arg is validated. Connection cache keyed by `user@host:port`. Forwards leak-free.   |
| `auth/oauth.py`      | File modes (0o700 dir / 0o600 files), atomic save, lazy expiry, single-client lockdown intact.    |
| `shelltools.py`      | `start_new_session=True` preserved (so `killpg` works). Env overlay does not propagate JSON errors. |
| `inventory.py`       | Wildcard `Host *` patterns are skipped in the flat listing. `resolve()` passthrough behavior holds. The raw ssh_config parse is retained so `ssh_config_aliases()` reports aliases that an inventory entry overrides. |
| `metrics.py`         | Counter / gauge label cardinality stays bounded. The `tool` label on resource reads is the STABLE name, never a user-controlled string. Hand-rolled exposition stays compliant (HELP + TYPE per metric, label escaping). The `syscall` label on the seccomp counters comes from the fixed `NOTIFIED_SYSCALLS` set. |
| `seccomp.py`         | Opt-in, default-off, `CAP_SYS_ADMIN`-gated; **never** latches `no_new_privs` (preserves set-uid/`sudo`). The supervisor only ever answers CONTINUE — it must never block/kill a child. `SECCOMP_FILTER_VERSION` bumps on any filter / notified-set change. `syscall_notify` events carry raw scalar register args only — no buffer dereference. Paired tests in `tests/test_seccomp.py`; the privileged paths are `seccomp`-marked. |
| `verifier.py`        | Template lookup tries packaged `_deploy` first, then source-tree `deploy/`. Each pair in `DEFAULT_PAIRS` has a stable `name`; new pairs must be reflected in `docs/deployment.md` §10. |

### 3.3 Security-sensitive diffs

Trigger an extra review pass if the diff touches:

- `patterns.py`, `audit.py`, `redaction.py`, `policy.py`
- The `Relay.run()` body in `server.py` or any resource handler
- `auth/oauth.py` (any TTL, store, or token-shape change)
- `metrics.py` (label-cardinality and label-value-escaping invariants are part of the trust boundary - a model that controls a label could otherwise smuggle data into the exposition)
- `seccomp.py` (the BPF filter, the notified-syscall set, the `CAP_SYS_ADMIN` gate, or the never-`no_new_privs` / always-CONTINUE invariants - a change here can alter the audit shape or the no-sandbox posture)
- `deploy/install*.sh` (anything that writes a systemd unit / EnvironmentFile)
- `deploy/Caddyfile` (CIDR matcher or header changes)

If you are reviewing through Claude Code, the bundled `/security-review`
skill scans the current diff and surfaces common findings in one pass;
that is the lowest-friction option. Without it, walk the diff against
this manual checklist:

- audit-record fields unchanged (`ts, tool, tier, denied, args,
  output_sha256, output_len, exit_code`), output body still hashed only;
- if `audit_chain` is enabled, the `seq`/`prev`/`chain` fields are
  *additive only* (the default-off record stays byte-identical) and
  `relay-shell --verify-audit` passes on a freshly written log;
- if the seccomp-notify channel is touched: it stays opt-in +
  `CAP_SYS_ADMIN`-gated and never latches `no_new_privs` (set-uid/`sudo`
  preserved); the supervisor only ever answers CONTINUE; `syscall_notify`
  events carry no dereferenced buffer; the per-call record and the spawn path
  stay byte-identical when the channel is off;
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
   maintainer forgot to bump `len(names) == 21`.
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

### 4.3 Coverage (CI floor: 90%, current ~92%)

`coverage` is in the dev extra and runs as part of the CI loop with a
90% floor that fails the workflow on regression. Reproduce locally:

```bash
# One-time: wire subprocess coverage so the stdio e2e contributes.
python -c "import site, pathlib; \
  pathlib.Path(site.getsitepackages()[0], 'coverage_subprocess.pth') \
    .write_text('import coverage; coverage.process_startup()\n')"

export COVERAGE_PROCESS_START=$(pwd)/pyproject.toml
coverage erase
coverage run -m pytest -q
coverage combine
coverage report           # uses fail_under=90 from [tool.coverage.report]
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
After B-022, `sshpool.py` is at ~96% and `server.py` wrapper bodies are
at ~95%. The remaining gap is in `sessions.py` (~85%; OS-specific
BlockingIOError + NotImplementedError fallbacks) and `auth/oauth.py`
(~84%; HTTP transport only).

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

(All currently listed items closed. New entries land here when a
consolidation opportunity shows up during an audit pass.)

Closed (do not re-add):

- **C-001** `SshPool` gained an idle reaper. `RELAY_SHELL_SSH_IDLE_TIMEOUT`
  (default 1800s) drops a cached connection that has not been used for
  that many seconds the next time `connect()` is consulted; mirrors the
  shape of `SessionRegistry._sweep`. `0` disables idle eviction (closed
  connections are still purged). `server_info.ssh` reports the live value.
- **C-002** The four sources of truth (registered tools, `_EXPECTED`,
  `docs/tools.md`, README capability tables) are pinned by tests in
  `tests/test_server.py` — any drift fails a PR.
- **C-003** `Relay.connect_kwargs` accepts an optional `connect_timeout`
  keyword; `ssh_check` and `ssh_fanout` use it via the helper. Zero /
  negative overlays drop the key so the pool's settings default fires.
- **C-004** `_INSTRUCTIONS` is asserted to mention every registered tool
  in `tests/test_server.py::test_server_instructions_mentions_every_tool`;
  the test catches drift on add or rename.
- **C-005** `Inventory` field naming resolved in PR #57. The constructor
  takes `ssh_config` (matching `Settings.ssh_config`); `ssh_config_file`
  is a *distinct* property — the resolved path iff the file exists on
  disk, vs the raw input path — kept deliberately because the two names
  mean different things (see the `Inventory.ssh_config_file` docstring).
  There is no third name to settle. The code carries no `ssh_config_path`.
  (Surfaced as F-005 in the 2026-06-01 ADR 0005 pass — this entry had gone
  stale here after the rename landed.)

### 5.2 Refactor candidates

- **R-001 Extract a `ToolDef` table.** `server.py` is mostly identical
  `@mcp.tool()` wrappers. A small table-driven registration
  (tool name, default tier override, work function, audit-args extractor)
  would cut the file in half and make adding a tool a one-line change.
  Risky if rushed - keep one PR per row migrated.
- **R-004 OAuth store backend interface.** `_Store` is hard-coded to JSON
  files. Promote it to a `Protocol` so an operator could plug in a
  Redis-backed store without touching `FileOAuthProvider`. Only worth
  doing if a second store is genuinely on the roadmap.

Closed (do not re-add):

- **R-002** `policy_text` builders extracted: every tool with a non-empty
  policy surface assembles its probe text through exactly one module-level
  `_policy_text_<tool>` function in `server.py` (greppable contract:
  "everything the executor sees, the policy sees"), pinned by
  `tests/test_tool_wrappers.py::test_policy_text_builders_include_every_executor_visible_part`.
- **R-003** Shared session registration: `Relay.register_session` is the
  one registry-add path for `shell_spawn` / `ssh_spawn`. Implemented as a
  `Relay` method rather than the suggested standalone factory module — ten
  lines next to their only two callers beat a new architecture-table row.
  Closing it also fixed a real leak: when `sessions.add` refused (session
  limit), the already-spawned transport (local PTY child or SSH process)
  was left running unsupervised; the shared path now closes the transport
  before the error propagates
  (`tests/test_sessions.py::test_register_session_closes_transport_when_registry_refuses`).

### 5.3 Tests to add (gap analysis)

(All currently listed items closed. New entries land here when a gap
shows up during an audit pass.)

Closed (do not re-add):

- **T-003** `tests/test_sessions.py::test_session_recv_ended_message_shape_with_exit`
  and `..._without_exit` pin both branches of the closed-session
  sentinel (`[session ... ended, exit=N]` and `[session ... ended]`).
- **T-004** `tests/test_ssh_integration.py::test_close_forward_swallows_listener_close_exception`
  injects a listener whose `close()` / `wait_closed()` raise; the
  pool's `contextlib.suppress(Exception)` swallows the failure and the
  tool still returns `closed forward {fid}`.
- **T-005** `tests/test_util.py` carries four hypothesis-driven
  properties for `truncate`: valid UTF-8 output, passthrough below the
  byte budget, marker presence above it, and bytewise prefix safety.

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

### 6.6 Cut a release (PyPI via OIDC trusted publishing)

The release path is driven by `.github/workflows/release.yml`. It runs
on any `v*` tag push (and on `workflow_dispatch` with an existing tag
as input). The workflow has three gated jobs:

  1. **verify** - the tag is annotated, GPG/SSH-signed and verified by
     GitHub, and matches the `[project] version` in `pyproject.toml`.
     A lightweight tag or an unsigned annotated tag fails here, before
     anything is built.
  2. **build** - dev install on Python 3.12, full test suite, then
     `python -m build` + `twine check` against the produced
     wheel + sdist.
  3. **publish** - runs in the `pypi` GitHub environment; uses OIDC
     (`pypa/gh-action-pypi-publish`) to upload to PyPI. No long-lived
     token. The environment is configured with a required reviewer so
     a human approval clicks between tag push and PyPI publish.

Pre-conditions (one-time setup, already done):

- PyPI trusted-publishing form configured at
  https://pypi.org/manage/account/publishing/ with
  `project=relay-shell`, `owner=rmednitzer`, `repository=relay-shell`,
  `workflow=release.yml`, `environment=pypi`.
- GitHub repo Settings -> Environments -> `pypi` exists with a required
  reviewer rule (so an unauthorized push of a malicious commit followed
  by a signed tag still needs a human click).

Per-release procedure:

```bash
# 1. Bump pyproject.toml version (e.g. 0.1.0 -> 0.1.1).
# 2. Update CHANGELOG.md: rename `[Unreleased]` to `[0.1.1] - YYYY-MM-DD`
#    and start a fresh empty `[Unreleased]` block above it.
# 3. Commit + open PR + land it via the normal review path.
# 4. After the bump is on main, sign-tag from main:
git tag -s v0.1.1 -m "Release v0.1.1"
git push origin v0.1.1
# 5. The release workflow starts. Approve the `pypi` environment when
#    GitHub asks. Watch the run; when publish turns green the wheel
#    + sdist appear at https://pypi.org/project/relay-shell/.
```

If the workflow fails mid-flight (e.g. PyPI is briefly down), re-run
it from the Actions UI via `workflow_dispatch` with the same tag. The
verify + build jobs are idempotent; the publish step passes
`skip-existing: true` to `pypa/gh-action-pypi-publish`, so any file
that already landed on PyPI from a previous attempt is silently
skipped instead of producing a "file already exists" failure. PyPI
itself enforces version immutability - this flag is the documented
way to make the re-run path safe.

If you need to yank a release, do it from the PyPI project page; this
project does not maintain a yank automation because yanks are rare and
the manual click is the appropriate friction.

---

## 7. Backlog

Prioritized. "P0" = blocking the next release. "P1" = should land in the
next milestone. "P2" = good-to-have, not blocking. "P3" = nice idea, no
commitment.

### 7.1 Capability

- **F-6 (P2)** — **Closed**. `ssh_upload` / `ssh_download` gained an explicit
  `timeout=` parameter (clamped to the server max), mirroring `ssh_exec`.
  Threaded through `SshPool.sftp_put` / `sftp_get` via `asyncio.wait_for`; a
  timed-out transfer returns `[TIMEOUT after Ns]`. `0` (default) disables the
  per-call cap (connection keepalive still applies), so existing callers are
  unaffected. Wiring tests in `tests/test_sshpool_unit.py` assert the cap fires
  (put + get) and that `timeout=0` completes. Originally deferred from the
  2026-05-27 engagement (`audit/2026-05-27-engagement.md` §8.2 F-6).

### 7.2 Quality + automation

(Items in this category are tracked here as they land; the queue is
currently empty. B-022 closed by the sshpool fault-injection PR -
floor is now 90%, baseline ~92%. The 2026-06-12 audit pass — evidence
under `audit/`, deferral register in `BACKLOG.md` — closed two more:
**QUAL-1** (PR #89), explicit observable asserts on the five seccomp
termination tests in `tests/test_seccomp.py`; and **REL-1** (PR #92),
the four HTTP `/metrics` tests migrated off the deprecated
`starlette.testclient` onto httpx's own `ASGITransport`, taking the
default suite from one warning to zero with no dependency change.)

### 7.3 Operations + observability

(Items in this category are tracked here as they land; the queue is
currently empty. B-014 closed by PR #47 — `RELAY_SHELL_AUDIT_FORMAT`
shipped with `jsonl`/`cef`/`leef` formatters in
`src/relay_shell/audit.py`.)

### 7.4 Docs and contribution

(Items in this category are tracked here as they land; the queue is
currently empty.)

### 7.5 Security hardening (incremental, no posture change)

- **B-021 (P3)** — **Closed** by
  [ADR 0006](adr/0006-seccomp-notify-audit-channel.md) (now Accepted): the
  opt-in, audit-only seccomp-notify channel shipped in
  `src/relay_shell/seccomp.py` (`RELAY_SHELL_SECCOMP_NOTIFY`, default off). A
  per-call BPF USER_NOTIF filter + supervisor appends `syscall_notify` /
  `syscall_notify_overflow` lines for a spawned child's syscalls, never
  blocking (always answers CONTINUE). `CAP_SYS_ADMIN`-gated and never latches
  `no_new_privs`, so set-uid/`sudo` posture is preserved verbatim;
  Linux/`x86_64`/kernel ≥ 5.5; pure `ctypes`, no new dependency. Follow-ups
  below (B-024/B-025/B-026).
- **B-024 (P3)** — **Closed**. `prctl` joined the notified set, gated on the
  privilege-relevant `option` values (`PRCTL_NOTIFIED_OPTIONS` in
  `seccomp.py`: `PR_SET_DUMPABLE`, `PR_SET_KEEPCAPS`, `PR_SET_SECCOMP`,
  `PR_CAPBSET_DROP`, `PR_SET_SECUREBITS`, `PR_SET_NO_NEW_PRIVS`,
  `PR_CAP_AMBIENT`) via a new `eq-any` BPF predicate on `args[0]`, so
  high-volume benign options (`PR_SET_NAME`, glibc's `PR_SET_VMA`) never
  trap. `SECCOMP_FILTER_VERSION` bumped to 2. Paired positive / near-miss
  tests run portably through a classic-BPF simulator in
  `tests/test_seccomp.py` (the near-misses include the numerically-adjacent
  `GET` twins), plus a `seccomp`-marked live test that drives a real child
  through one notified and one near-miss `prctl`.
- **B-025 (P3)** `aarch64` support for the seccomp-notify channel. Deferred
  from B-021 (v1 ships `x86_64`-validated syscall numbers only; other arches
  no-op). Add the arch's syscall-number + `AUDIT_ARCH` tables and validate the
  notify round-trip on a live `aarch64` host before `platform_support()`
  admits it.
- **B-026 (P3)** — **Closed**. The seccomp-notify channel now covers local
  PTY sessions: `sessions.LocalPtyTransport.spawn` consults the same
  per-call monitor the one-shot executor uses, and the transport *adopts*
  it — the monitor lifetime follows the session (stopped in `aclose()`),
  the session child and everything it forks carry the filter, and events
  keep the spawning call's `request_id`. The cap therefore bounds events
  per session, not per call. The "SSH-local half" deferred from B-021 turned
  out to be vacuous as implemented: `asyncssh` runs in-process and
  `sshpool.py` spawns no local child (no `ProxyCommand` support is wired),
  so there is nothing local to observe on that path; if a local-subprocess
  proxy path ever lands, the ambient-monitor pattern covers it the same way.
  Tests: portable adoption/lifetime tests + a `seccomp`-marked end-to-end
  `shell_spawn` session test in `tests/test_seccomp.py`.
- **B-023 (P2)** — **Closed** by
  [ADR 0007](adr/0007-audit-hash-chain.md): an opt-in, additive
  tamper-evident audit hash chain (`RELAY_SHELL_AUDIT_CHAIN`, default
  off) — `seq`/`prev`/`chain` per record plus offline verification via
  `relay-shell --verify-audit`. Closes the in-record integrity gap (G-1)
  the 2026-06-01 audit pass surfaced: `chattr +a` + off-host shipping do
  not make a single altered record detectable, the chain does.
  Default-off keeps the record byte-identical, so no posture change.
- **SEC-1 (P3)** — **Closed** (PR #89; from the 2026-06-12 audit pass,
  IDs per `BACKLOG.md`). `ssh_keyscan` target hosts now reach the policy
  layer: `_policy_text_ssh_keyscan(hosts)` in `server.py` feeds the scan
  targets to `RELAY_SHELL_POLICY_DENY` (audited `denied=True` on a match,
  short-circuiting before any subprocess), closing the one gap in the
  R-002 contract and matching the transfer tools. Accepted tradeoff,
  documented in the builder docstring: the same text feeds the tier
  classifier, so a host name embedding a `\b`-bounded destructive word
  over-classifies above Tier 1 (bites only `guarded`;
  `RELAY_SHELL_POLICY_ALLOW` is the escape hatch). Paired tests in
  `tests/test_ssh_keyscan_tool.py`.
- **TOOL-1 + TOOL-3 (P3)** — **Closed** (PRs #89/#90). Secret scanning:
  `.gitleaks.toml` allowlists exactly the synthetic-fixture paths
  (`tests/*.py`, `docs/runbook.md`, `audit/*.md`; a canary under `src/`
  still trips), and `.github/workflows/gitleaks.yml` runs the scan on
  push to `main`, PRs, and daily — pinned gitleaks installed via the
  release's own checksums file, `permissions: contents: read`, fails on
  any finding. This also closes the **P1-2 gitleaks** CI gate deferred in
  `audit/2026-06-01-engagement.md` §7.2. The required-check decision was
  made and applied 2026-06-12 (see the F-G2 status note below).
- **SEC-2 (P3)** — **Closed** (PR #91). The `dependency-review` job
  dropped its checkout step and `persist-credentials: true` entirely:
  source-verified at the pinned action SHA that for `pull_request`
  events it reads base/head SHAs from the event payload and uses the
  Dependency Graph API only (no git subprocess, no working-tree read
  without a local `config-file` input). Self-validated on its own PR's
  check. The job now runs with no token persisted and no repo bytes on
  disk.
- Status note: **F-G2** (branch protection on `main`, carried since the
  2026-05-27 pack) is **fully resolved** as of 2026-06-12. Protection is
  a repository ruleset (`main-protection`, id 17307996; classic
  protection is unset), enforcing: pull_request (0 approvals,
  stale-review dismissal, thread resolution), non_fast_forward, deletion,
  required_linear_history, **required_signatures** (closing the prior
  pack's deferred **P2-3**), and **required_status_checks** — the three
  CI legs (`check (py3.12/13/14)`) plus `gitleaks (secret scan)`, all
  bound to GitHub Actions, strict=false. pip-audit / dependency-review /
  CodeQL stay advisory by operator choice (an upstream CVE disclosure
  must not block unrelated merges). Enumerated and applied via the
  operator's Vertex-held `gh` credential with explicit T3 confirmation;
  verified effective via `GET /rules/branches/main` after the change.

---

## 8. `.md` update run (per-file)

A single-pass cleanup of every Markdown file in the tree. Each entry below
lists what to add, what to keep, and what to remove. The intent is one PR
per file (or one PR for the whole batch if no behavior changes), reviewed
by the same checklist.

### 8.1 `README.md`

- Keep: title, DeepWiki badge, Why, Capabilities tables (local shell,
  SSH, sessions, diagnostics, resources), Quickstart, Security posture
  summary, Layout, Development, AI contributor guidance, License.
- Done (do not re-add):
  - Runbook link under "AI contributor guidance".
  - `/metrics` paragraph under Diagnostics.
  - Resources subsection.
  - Prompts subsection (the `operating_guide` prompt, audited like a
    resource read; ADR 0008).
  - Status line under the title (version, Python matrix, transports,
    last validation date with ADR pointer).
  - Compatibility matrix block (Python / host OS / transport / SDK /
    SSH library), refreshed on every validation pass.
- Cross-checks: capability tables must match `docs/tools.md` and
  `tests/test_server.py::_EXPECTED`. The Status line's "last
  validated" date must match the most recent ADR 0005 outcome
  paragraph.

### 8.2 `SECURITY.md`

- Keep: Model, Trust boundary, Deployment requirements, Residual risk,
  Reporting, Scope sections - they are accurate and pithy.
- Done (do not re-add):
  - "Disclosure timeline" subsection under "Reporting a vulnerability"
    (acknowledge in 7 days, fix or mitigation plan in 30, public
    advisory + credit when shipped).
- Add (still open):
  - A "Supported versions" table once the project tags a second
    release (today only 0.1.0 exists). Until then, omit rather than
    fake.
- Remove: nothing.

### 8.3 `CHANGELOG.md`

- Keep: Keep-a-Changelog format and the `[Unreleased]` section structure.
  Consolidate to one `### Added` / `### Changed` / `### Fixed` /
  `### Security` block per release - duplicated category headers under
  the same release confuse readers and break Keep-a-Changelog tooling.
- Update on every release: cut the `[Unreleased]` block, stamp the
  version + date, link diffs.

### 8.4 `AGENTS.md`

- Keep: Mission, Non-negotiables, References, Implementation standards,
  Change workflow, Repo map, Definition of done.
- Done (do not re-add):
  - Section 5 runbook pointer.
  - Section 6 canonical-tool-list note pointing at
    `tests/test_server.py::_EXPECTED`.
  - Section 6 entries for `patterns.py`, `metrics.py`, `verifier.py`.
- Remove: nothing.

### 8.5 `CLAUDE.md`

- Keep: Objective, Core behavior expectations, Required development loop,
  Coding guidance, GitHub optimization checklist, Trusted references.
- Done (do not re-add):
  - The runbook §2 note under "Required development loop".
  - The backlog-preference bullet under "When uncertain".
- Remove: nothing.

### 8.6 `docs/architecture.md`

- Keep: the diagram, request-lifecycle prose, module table (now
  including `metrics` and `verifier`), concurrency notes, transport
  notes (including the `/metrics` route on HTTP), security-model link.
- Done (do not re-add):
  - "Where the lifecycle maps in code" appendix linking each step to
    the exact `server.py` / `audit.py` / `util.py` call site.
  - `metrics`, `verifier` rows in the module table.
  - Pointer to `docs/runbook.md` §2 and ADR 0005 in the security-model
    section.
- Remove: nothing.

### 8.7 `docs/tools.md`

- Keep: the per-tool tables, the conventions header, the Tier reference
  sidebar (now present at the top), the Resources section, the
  interactive pattern example, the error grammar.
- Done (do not re-add):
  - Tier reference sidebar at the top of the file.
  - Resources section listing the three `relay-shell://...` URIs and
    the stable audit `tool` names.
  - Prompts section listing the `operating_guide` prompt and its stable
    audit `tool` name (`prompt:operating_guide`); ADR 0008.
  - Per-tool "Tests: ..." line giving the test file(s) that exercise
    each tool (file paths only - lines drift).
- Remove: nothing.
- Cross-checks: the set of tools listed here must equal
  `tests/test_server.py::_EXPECTED`. The default-tier note for each tool
  must match `policy._READ_ONLY_TOOLS` / `policy._MUTATING_TOOLS` / the
  `classify` function. Each tool's "Tests: ..." line must reference a
  file that actually exists under `tests/`.

### 8.8 `docs/deployment.md`

- Keep: every section. The deployment guide is accurate and
  worked-example heavy.
- Done (do not re-add):
  - §0 "Pre-flight checklist" (service account name, audit dir
    writable + append-only-capable filesystem, DNS A/AAAA resolves
    for the edge domain, ports 80/443 reachable, SSH service account
    keypair, off-host audit shipper ready).
  - §11 "Backup and restore" (`clients.json` / `codes.json` /
    `tokens.json` under the OAuth state dir, the
    `/etc/relay-shell/` EnvironmentFile, the audit log + rotations).
  - Link to `docs/runbook.md` §4.6 for the manual HTTP smoke in §9.
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
- Done (do not re-add):
  - "Operational notes" appendix listing the `journalctl -u caddy`
    invocation for cert issuance troubleshooting and the
    `caddy validate --config /etc/caddy/Caddyfile` invocation for
    drift detection.

### 8.12a `docs/adr/0005-codebase-validation.md`

- Keep: the validation methodology (steps 1-4), every dated outcome
  paragraph (2026-05-24, 2026-05-31, ...), and the rejected-alternatives
  section.
- Add on each subsequent validation pass: a new outcome paragraph
  + findings table dated to the pass. Do not overwrite prior dates;
  the ADR is a running record of validation events. Refresh the ADR
  index subject in `docs/adr/README.md` so it names every pass.
- Cross-checks: every finding row must reference the file + line the
  drift lived at and the same PR's resolution (so the audit trail is
  recoverable without `git blame`).

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
  ADR" criteria, the next-free-number marker (currently **0008**),
  and the cross-references to `docs/architecture.md` and
  `docs/runbook.md` §6.
- Add: a row to the index table whenever a new ADR lands. Update the
  status column when an ADR is superseded or deprecated. Bump the
  next-free-number marker every time an ADR file is created.
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

### 8.20 `audit/<date>-engagement.md` (assurance engagement packs)

- Keep: each dated engagement pack as a **frozen, point-in-time
  record**. It captures the repository at the HEAD it names
  (`audit/2026-05-27-engagement.md` is pinned to `823bd743`), the
  findings table, their disposition, and the PRs that closed them. Do
  not retro-edit a landed pack to match later state — like the ADR 0005
  outcome paragraphs, it records an *event*, not a living document.
- Add: a new `audit/YYYY-MM-DD-engagement.md` per subsequent
  engagement; do not overwrite a prior one. The pack is the broader
  assurance counterpart to an ADR 0005 validation pass — ADR 0005
  records the terse four-step upstream-surface check per pass, an
  engagement pack records a full audit / review / harden engagement
  (backlog disposition, findings by severity, cross-cutting standards
  posture, execution log).
- Remove: nothing.
- Cross-checks: every finding marked fixed must name the PR that closed
  it so the pack reconciles against the merged history without
  `git blame`. Any finding left open (e.g. F-G2 branch protection on
  `main`) must reappear in the next pack's outstanding-risks section
  until it is closed.

### 8.21 `BACKLOG.md`

- Keep: the Closed table (resolutions with their PRs), the per-category
  open tables with the audit-charter schema (ID, severity, effort,
  rationale, approach, dependencies, owner role), and the pointer naming
  this runbook §7 as the canonical living backlog.
- Add: a row per finding an audit pass defers; move it to the Closed
  table (never delete it) when the work lands, naming the closing PR.
- Remove: nothing; like the engagement packs, closed rows are the audit
  trail.
- Cross-checks: every open row must trace to a findings-register ID in
  the `audit/` pack that produced it; anything that belongs to the
  *ongoing* queue (not an audit deferral) lives in §7 here, not in
  `BACKLOG.md` — when an item is recorded in both (e.g. SEC-1), the two
  entries must name the same closing PR.

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
