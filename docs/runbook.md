# Maintenance Runbook

A working procedure for auditing, reviewing, enhancing, validating, and
extending `relay-shell`. Pair it with [`AGENTS.md`](https://github.com/rmednitzer/relay-shell/blob/main/AGENTS.md) and
[`CLAUDE.md`](https://github.com/rmednitzer/relay-shell/blob/main/CLAUDE.md): those define the operating contract, this is
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

The backlog (§7) is the queue of ongoing work; `BACKLOG.md` is the register of
audit-pass deferrals. §8 lists the documentation conventions that keep the
`.md` files consistent with the code.

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
output_len, exit_code` at minimum. `request_id`, `client_id`, and `action`
are context-dependent and may be absent (`action` is `confirm_plan` /
`confirm_execute` only under the Tier-3 confirmation broker,
`RELAY_SHELL_CONFIRM_TIER3`; ADR 0009; `cancelled` when the caller went away
mid-call; `intent` only under the opt-in write-ahead record
`RELAY_SHELL_AUDIT_INTENT`). Absence of any of the *required*
fields above is an audit regression; the default-off broker keeps the
record byte-identical (no `action` field).

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
RELAY_SHELL_MAX_FORWARDS=64 \
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
print('per-call weaker mode allowed:', s.ssh_allow_weaker_known_hosts)
"
```

For production: `ssh_known_hosts` should be `strict` and
`ssh_allow_weaker_known_hosts` `false`, so a caller cannot pass `known_hosts=ignore` per
call. `accept-new` is trust-on-first-use (a known host is verified, a changed key is refused)
and is fine for dev. `ignore` outside tests is a finding. An inventory entry may still set its
own `known_hosts` (it is operator-written); the audit record shows the mode actually used.

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
# Off-host shipping running?  The shipper itself is deployment-specific; if the
# bundled verifier/sync (deploy/evidence/) is installed, check the anchor:
jq '{valid, generated_at, latest_seq, retention_pruned_head}' /var/log/relay-shell/latest-anchor.json
systemctl status relay-audit-evidence.timer
```

`valid` must be `true` and `generated_at` recent; `valid: false` or a stale anchor means
off-host publishing has stopped (read `chain-verification.jsonl` for the errors). A degraded
audit (a bad path at start-up, a non-regular sink, or a write that failed at runtime) is
reported in `server_info().audit.degraded`. That flag flipping to `true` in production
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
| `audit.py`           | Output body never written, only `sha256` + `len`. `degraded` path still degrades, not crashes, and a runtime write failure (not just a bad path at start-up) sets `degraded`, and so does a seccomp-notify monitor that fails open (`mark_degraded`, first reason kept; ADR 0006). With `audit_chain` on, `seq`/`prev`/`chain` are appended under `_chain_lock` and `verify_chain` round-trips (ADR 0007); the default-off path is byte-identical. |
| `redaction.py`       | Consumes `patterns`; the loop order (URL creds → prefix patterns → whole-match patterns → MySQL family) is unchanged. |
| `sessions.py`        | Lost-wakeup invariant: `recv` clears the event under the buffer lock before awaiting. PTY spawn adopts the active seccomp monitor; the transport stops it in `aclose()` — on the failure path too (B-026). A session that has left the registry (`close`, `_sweep`, `shutdown`) is torn down by its own shielded task, so a cancelled caller cannot strand it (ADR 0012, with the STPA trace); `LocalPtyTransport.aclose` sends SIGKILL if cancelled during the SIGTERM grace wait. |
| `sshpool.py`         | `known_hosts` arg is validated and, when `RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false`, may not weaken the server default. The connection cache key includes user, port, verification mode, identity key and jump host; a failed or cancelled connect always releases its single-flight slot. `L:`/`D:` forwards listen on loopback only. Forwards leak-free, including a cancel between binding a listener and tracking it, and between opening an `ssh_spawn` channel and its transport owning it. A caller-supplied host, user and jump hop must be a plain token (`_check_ssh_tokens`): they are substituted into the operator's `ProxyCommand`, so whitespace or a leading `-` would add local argv. |
| `auth/oauth.py`      | File modes (0o700 dir / 0o600 files), atomic save (unique temp, fsync, rename; ownership of the state dir kept when run as root), approval written before the client, lazy expiry, single-client lockdown intact, refusals raised as `RegistrationError`/`TokenError` (never a bare exception), every grant bound to the configured resource. |
| `auth/admin.py`      | Approve / reject only touch the named client's approval, codes and tokens; an unreadable store is an error, not empty. |
| `shelltools.py`      | `start_new_session=True` preserved (so `killpg` works). Env overlay does not propagate JSON errors. |
| `inventory.py`       | Wildcard `Host *` patterns are skipped in the flat listing. `resolve()` passthrough behavior holds. The raw ssh_config parse is retained so `ssh_config_aliases()` reports aliases that an inventory entry overrides. |
| `metrics.py`         | Counter / gauge label cardinality stays bounded. The `tool` label on resource reads is the STABLE name, never a user-controlled string. Hand-rolled exposition stays compliant (HELP + TYPE per metric, label escaping). The `syscall` label on the seccomp counters comes from the fixed `NOTIFIED_SYSCALLS` set. |
| `seccomp.py`         | Opt-in, default-off, `CAP_SYS_ADMIN`-gated; **never** latches `no_new_privs` (preserves set-uid/`sudo`). The supervisor only ever answers CONTINUE — it must never block/kill a child, and `stop()` must not close a listener that a surviving process still needs (it hands it to the detached server, ADR 0006 correction). `SECCOMP_FILTER_VERSION` bumps on any filter / notified-set change. `syscall_notify` events carry raw scalar register args only — no buffer dereference. Paired tests in `tests/test_seccomp.py`; the privileged paths are `seccomp`-marked. |
| `verifier.py`        | Template lookup tries packaged `_deploy` first, then source-tree `deploy/`. Each pair in `DEFAULT_PAIRS` has a stable `name`; new pairs must be reflected in `docs/deployment.md` §10. |

### 3.3 Security-sensitive diffs

Trigger an extra review pass if the diff touches:

- `patterns.py`, `audit.py`, `redaction.py`, `policy.py`
- The `Relay.run()` body in `server.py` or any resource handler
- `auth/oauth.py` (any TTL, store, or token-shape change)
- `metrics.py` (label-cardinality and label-value-escaping invariants are part of the trust boundary - a model that controls a label could otherwise smuggle data into the exposition)
- `seccomp.py` (the BPF filter, the notified-syscall set, the `CAP_SYS_ADMIN` gate, or the never-`no_new_privs` / always-CONTINUE invariants - a change here can alter the audit shape or the no-sandbox posture)
- `broker.py` (ADR 0009 Tier-3 confirmation broker: the plan->execute token identity/binding, its TTL, and the always-*after*-the-deny/mode-check layering - a change here can weaken the friction on irreversible operations or, if it ran before the deny/mode check, turn a safeguard into a bypass)
- `deploy/evidence/*` (the audit-evidence verifier and sync: a change that relaxes what counts as a valid anchor stops the anti-tail-truncation control working) and `.github/workflows/release.yml` / `sbom.yml` / `requirements-build.txt` / `requirements-sbom.txt` (the jobs that build, sign and publish: privileges must stay separate from package installs)
- `sshpool.py` (host-key verification, the connection-cache key, forwards)
- `verifier.py` (the `relay-shell --verify-deploy` drift comparator: a change that silently widens the byte-for-byte comparison, or the single-leader-line strip it allows, could report `OK` for a hand-edited systemd unit or Caddyfile - the same class of hardening-regression the comparator exists to catch)
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
   maintainer forgot to bump `len(names) == 22`.
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

If the test command is itself launched through a running Relay instance whose
seccomp-notify channel is enabled, the live `seccomp` tests inherit the outer
tool call's listener. Linux permits only one user-notify listener in a filter
hierarchy, so the nested install returns `EBUSY` and is an environment artifact,
not a product failure. Run that marked suite from a fresh PID 1 child instead:

```bash
sudo systemd-run --wait --pipe --collect \
  --uid="$(id -un)" --gid="$(id -gn)" \
  --working-directory="$PWD" --setenv=PYTHONPATH=src \
  -p AmbientCapabilities=CAP_SYS_ADMIN \
  -p CapabilityBoundingSet=CAP_SYS_ADMIN \
  "$PWD/.venv/bin/pytest" -q -m seccomp tests/test_seccomp.py
```

Keep the transient unit scoped to `CAP_SYS_ADMIN`; do not disable the running
Relay channel or relax its service posture just to execute the tests.

### 4.3 Coverage (CI floor: 90%, last measured 93%)

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
Last measured (2026-10-14, as root so the live `seccomp` tests ran, no subprocess
collection): 93% total; `policy`, `redaction`, `patterns`, `broker`, `metrics`,
`auth/admin` at 100%; `sshpool.py` 97%, `server.py` 97%, `seccomp.py` 96%,
`auth/oauth.py` 93%, `audit.py` 95%. The remaining gaps are `sessions.py` (~88%;
OS-specific BlockingIOError + NotImplementedError fallbacks), `inventory.py` (~91%) and
`__main__.py` (~56% without subprocess collection: the CLI tests run the program as a
subprocess, so use the recipe above). A non-root runner (GitHub Actions) skips the live
`seccomp` tests and reports less for `seccomp.py`. `branch = true` is not enabled, so
untaken branches inside covered lines are not reported.

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

When the tag lands, `.github/workflows/release.yml` builds and publishes to
PyPI via OIDC trusted publishing (verify → build → attest → publish; the full
procedure and the one-time PyPI / `pypi`-environment setup are in §6.6), and
`.github/workflows/sbom.yml` generates a CycloneDX SBOM (JSON + XML, CDX
spec 1.5, pinned) for the package's runtime environment, attaches both files to the
GitHub release, and attests their build provenance. Both workflows install their
tooling from the hash-locked `requirements-build.txt` / `requirements-sbom.txt`
(§6.6 says how to regenerate them). B-005 (PyPI publish automation)
closed in 0.1.0 with `release.yml`; the one-time PyPI trusted-publisher /
`pypi`-environment setup is documented in §6.6.

---

## 5. Enhance (consolidation and cleanup)

Discrete, low-risk improvements you can ship without changing the public
surface. The intent is to leave the next contributor a smaller surface area
and clearer code, not to land a refactor for its own sake.

### 5.1 Consolidation candidates

None open. Closed items (C-001..C-005: SSH idle reaper, tool-contract drift
tests, `connect_kwargs` timeout, `_INSTRUCTIONS` coverage test, `Inventory`
naming) are recorded in `CHANGELOG.md` and pinned by tests; new entries land here
when an audit pass finds a consolidation opportunity.

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

Closed: **R-002** (one `_policy_text_<tool>` builder per tool, pinned by
`tests/test_tool_wrappers.py::test_policy_text_builders_include_every_executor_visible_part`)
and **R-003** (`Relay.register_session` is the single registry-add path and closes the
transport when the registry refuses).

### 5.3 Tests to add (gap analysis)

None open from the runbook. The 2026-10-14 pass records its remaining coverage gaps
(auth expiry / `client_id` mismatch branches, `verify_chain` `prev` mismatch,
`session_kill` signal parsing, `ssh_spawn` / transfer success wrappers) in
`BACKLOG.md`.

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
     executor will see (command + stdin + env_json + script body; for an SSH tool
     also the destination host and any jump host);
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
   (classifies as expected) and one *negative* near-miss case (a form the
   start anchor rejects — the keyword sitting mid-token, so `(?<![\w])`
   for TIER2/TIER3, or `\b` for `PRIV_ESC_PATTERN`, does not fire).
3. Document the addition in `docs/adr/0003-tiered-authority.md` if the
   heuristic represents a new category (not just another verb).
4. Never replaces the deny list as a security control. The heuristics
   are advisory in `open` mode; the deny list is the only guarantee.
5. Keep the pattern linear. The classifier runs synchronously on the event loop before
   the deny list, so bound every repetition (`{0,N}` rather than `*`/`+` on a class that can
   match whitespace or the pattern's own separator) and never put two adjacent quantifiers
   over overlapping classes. Add a time-ceiling test with a 20-100 KB adversarial payload
   (whitespace runs, repeated `dd `/`rm `) next to the positive/near-miss pair, and run
   `pytest -m fuzz -v` (the fuzz inputs are short, so they do not replace that test).
6. `policy.classify` removes shell line continuations before matching and ignores a
   privilege wrapper that only appears in a read-only segment (`grep sudo ...`,
   `PRIV_ESC_READER_SEGMENT`). A new command-name rule belongs in command position (`_CMD`)
   so that `man <command>` does not trigger it; add the near-miss to
   `tests/test_classifier_v16.py`.

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
4. Redaction runs on every audit record on the event loop: keep the rule linear (bounded
   repetitions, no nested quantifiers) and add a time-ceiling test with a 10-20 KB payload that
   would trigger the worst case (for example `-1` repeated), as in
   `test_cli_flag_redaction_is_not_quadratic_on_hyphen_digit_runs`.
5. The `COMMAND_SCOPED_PREFIX_PATTERNS` table holds flags that are only secrets for one
   command (`redis-cli -a`, `unzip -P`, `ldapsearch -w`, `aws configure set`). Add a
   command-scoped rule there rather than a bare `-x` rule, and a near-miss for the same flag
   on another command.
6. An unquoted value stops at an unquoted shell control operator (`;`, `&`, `|`), shared as
   `_VALUE_RUN` in `patterns.py` (v15), so a command glued to a secret is not swallowed;
   tests in `tests/test_redaction_operators.py` pin both directions. Copy that behaviour
   into any new rule with a bare value.

### 6.6 Cut a release (PyPI via OIDC trusted publishing)

The release path is driven by `.github/workflows/release.yml`. It runs
on any `v*` tag push (and on `workflow_dispatch` with an existing tag
as input; a dispatch run is only trusted from `main`). The workflow has four gated jobs:

  1. **verify** - the tag is annotated, GPG/SSH-signed and verified by
     GitHub, and matches the `[project] version` in `pyproject.toml`.
     A lightweight tag or an unsigned annotated tag fails here, before
     anything is built.
  2. **build** - dev install on Python 3.14 (direct pins from `requirements.txt` as
     constraints), full test suite, then `python -m build --no-isolation` +
     `twine check`. The build tooling (`build`, `twine`, `hatchling`) comes from the
     hash-locked `requirements-build.txt`; the job holds a read-only token and no OIDC.
  3. **attest** - downloads the dist artifact and signs the SLSA build-provenance
     attestation. It installs nothing, so the `id-token` / `attestations` permissions
     never share a job with package installs.
  4. **publish** - runs in the `pypi` GitHub environment; uses OIDC
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

The hash-locked tooling files are generated, not hand-edited. To refresh after a tooling
bump (Renovate proposes updates; regenerate to keep transitive hashes consistent):

```bash
uv pip compile requirements-build.in --generate-hashes --python-version 3.14 -o requirements-build.txt
uv pip compile requirements-sbom.in  --generate-hashes --python-version 3.14 -o requirements-sbom.txt
pytest -q tests/test_release_workflows.py   # pins shared with requirements.txt must agree
```

The lock files are fetched by SHA (`gh api .../contents/<lock>?ref=$GITHUB_SHA`) from the
commit the workflow runs at, not from the release checkout, so recovering or backfilling an
older tag that predates them still works (a dispatch is only trusted from `main`). The SBOM
spec version is pinned with `--sv 1.5` because `cyclonedx-bom` 7.x defaults to 1.6.

`sbom.yml` is split the same way: a read-only `sbom` job builds the runtime-only SBOM with
the hash-locked `cyclonedx-bom` from a separate venv, and a `publish` job (contents: write +
OIDC, no installs) attests it and creates the release.

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
- **L1 confirmation broker (P1)** — **Closed** by
  [ADR 0009](adr/0009-tier3-confirmation-broker.md) (2026-07-15 pass): an opt-in,
  default-off two-step confirmation gate for Tier-3 (IRREVERSIBLE) operations
  (`RELAY_SHELL_CONFIRM_TIER3`). `Relay.run` returns a single-use, TTL-bounded
  token bound to `sha256(tool \0 policy_text)` (audited `confirm_plan`) and the
  caller arms it via the new `operation_confirm` tool then re-issues the exact
  call (audited `confirm_execute`). Adapted from the sibling MCP planes'
  plan → authorize → execute broker; layered after the deny/mode check (never a
  bypass); default-off byte-identical. `src/relay_shell/broker.py` (100%
  covered), `tests/test_broker.py`; tool contract 21 → 22.
- **BRK-2 (P3)** — rollback/verify pairing for the confirmation broker
  (`rollback_command` / `verify_command` / `auto_rollback`), the part of the
  sibling brokers deferred from ADR 0009. Now has its own ADR:
  [ADR 0010](adr/0010-rollback-verify-broker.md) (**Proposed**) specifies the
  design and the seven invariants a build must satisfy (chiefly: rollback/verify
  are themselves fully deny-list/tier-gated, never a policy bypass; bound into
  the confirmation identity; three distinct audit records; bounded, non-recursive
  loop) and **decides to defer** until a concrete trigger — an autonomous /
  unattended deployment, or an operator ask for operation-bound remediation that
  survives the issuing turn — since a model can already sequence verify/rollback
  itself in the attended case. Move ADR 0010 to Accepted with the implementing PR
  when a trigger is real.
- **WIN-1** — first-class support for **Windows targets over OpenSSH with
  PowerShell 7**, per [ADR 0011](adr/0011-windows-openssh-powershell.md)
  (**Accepted**). Execution + SFTP already work (asyncssh passes the raw command
  to the remote's own shell); the gap was that the tier classifier was
  POSIX-only, so pwsh destructive cmdlets (`Remove-Item -Recurse -Force`,
  `Clear-Disk`, `Stop-Computer`, `Remove-Service`, …) under-classified as Tier 1
  and escaped `guarded`/`readonly` mode and the ADR 0009 broker. Increments
  **A** (pwsh-aware Tier-2/3 + priv-esc patterns — same anchoring/ReDoS
  discipline, POSIX byte-identical, `PATTERNS_VERSION` 9→10, paired FP tests) +
  **B** (docs §8b) and **C** (PowerShell credential redaction —
  `credential` keyword + `ConvertTo-SecureString` inline-plaintext rule +
  `Verb-Noun` over-scrub guard; `PATTERNS_VERSION` 11) **landed**.
  Encoding/PTY (D/E) stay documented caveats (pwsh is UTF-8 by default). No
  command/path translation layer, no new transport/tool. Classification and
  redaction stay heuristic (ADR 0003) — a positional secret with no keyword is
  not redactable.

### 7.1a 2026-10-04 audit pass (register)

Evidence: the PR descriptions of #189-#197 (no `audit/` pack was archived for this
pass; H = high, M = medium, L = low). Every finding below was reproduced by running
code before it was fixed; each fix landed with paired tests that fail against the old
code. The 2026-10-14 pass is recorded in `BACKLOG.md` and `audit/2026-10-14-engagement.md`.

| ID | Finding | Status |
|----|---------|--------|
| H1 | Cancelled / disconnected calls were not audited and the command kept running | **Closed** (#190): `action=cancelled` record, process group killed, remote terminated; opt-in `RELAY_SHELL_AUDIT_INTENT` write-ahead record covers a relay crash |
| H2 | `accept-new` disabled host-key verification on every connect | **Closed** (#189): known hosts verified, a changed key refused, canonical `[host]:port` persistence, fail closed on a corrupt entry |
| H3 | SSH connection-cache key ignored `known_hosts` / `key_path` / `jump` | **Closed** (#189) |
| H4 | OAuth: no authentication step, first registrant won, corrupt `clients.json` reopened registration | **Closed** (#192): operator approval (`--auth-list` / `--auth-approve` / `--auth-reject`), fail closed on an unreadable store |
| H5 | `session_send` input audited verbatim (typed sudo passwords) | **Closed** (#191): withheld at a secret prompt; `RELAY_SHELL_AUDIT_SESSION_INPUT=hash` |
| M1 | Redaction missed quoted multi-word values, hyphenated secret flags, `curl -u`, `sshpass -p`, `docker login -p`, `openssl -pass`, URL passwords with `@` | **Closed** (#191, `PATTERNS_VERSION` 12). A URL password containing `/` is not distinguishable from a path and stays unredacted |
| M2 | Tier classifier false positives (read-only commands at Tier 3) and false negatives | **Closed** (#194, version bump to 13 in #197) |
| M3 | A command split across `session_send` calls bypassed classification | **Closed** (#194): the line being typed is classified |
| M4 | Admission scans unbounded input synchronously | **Closed** (#195): `RELAY_SHELL_MAX_INPUT` |
| M5 | Unauthenticated HTTP accepted on a non-loopback address | **Closed** (#195): refused unless `RELAY_SHELL_ALLOW_UNAUTH_NETWORK=true` |
| M6 | Transfer / forward / spawn audit records omitted the connection identity | **Closed** (#191) |
| M7 | `ssh_check` was Tier 0 for any host | **Closed** (#195): Tier 1 for hosts outside the inventory |
| M8 | OAuth tokens stored raw, files unbounded, per-request read on the event loop | **Closed** (#193): hashed at rest, purged on write, read off the loop. No in-memory cache (it would need cross-process invalidation) |
| L1, L2, L3, L5, L6, L7, L9 | Unretrieved future, lingering channel reported as timeout, raw traceback on a bad deny regex, audit docstring, UTF-8 split in `session_recv`, `.env` from the working directory, `ProxyJump none` | **Closed** (#196) |
| L4 | Seccomp (opt-in): `preexec_fn` in a multithreaded process, `openat2` / `creat` not notified, `monitor.stop()` joins on the event loop | **Deferred**: cannot be verified without `CAP_SYS_ADMIN`; needs a privileged host and its own PR |
| L8 | No transitive dependency lock with hashes; Renovate extends an external preset | **Deferred**: a CI and release-process decision, not a code fix |

Residual by design: classification and redaction stay heuristic (ADR 0003); the
OAuth CLI and the server share no lock (a lost update is fail-safe); a secret typed
at a prompt the heuristic does not recognise is still recorded unless the `hash`
mode is on.

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

The 2026-06-21 full audit pass closed **QUAL-2 (P3)** (`ssh_forward` now raises a
bounded error on a malformed spec) and **FMT-1 (P3)** (the LEEF formatter emits
the mandatory LEEF 2.0 delimiter field) in the P2/P3 follow-up PR. **FMT-2
(info)** (CEF header-field escaping — no runtime defect) is **Closed** (PR #111,
`_cef_header_escape`; header fields are constants so the bytes are byte-identical,
the escape is structural insurance against a future dynamic header field). Full
detail in [`BACKLOG.md`](https://github.com/rmednitzer/relay-shell/blob/main/BACKLOG.md) (2026-06-21 section) and
[`audit/2026-06-21-engagement.md`](https://github.com/rmednitzer/relay-shell/blob/main/audit/2026-06-21-engagement.md).

The **2026-08-04 audit + gap-analysis pass** (`audit/2026-08-04-engagement.md`)
closed three MEDIUM defence-in-depth / correctness gaps in the engagement PR
(CONN-1/CONN-2/EDGE-3); the **2026-08-04 backlog follow-up**
(`audit/2026-08-04-backlog-followup.md`) then closed the two deferred items
(EVID-1, PERF-4):

- **CONN-1 (P2)** — **Closed**. `RELAY_SHELL_MAX_CONNS` (default 256) hard-bounds
  the `SshPool._conns` connection cache with LRU-unpinned eviction, mirroring
  `max_sessions` / `max_forwards` for the cache beneath them (idle eviction was
  the only prior bound and is opportunistic + unbounded in count).
- **CONN-2 (P2)** — **Closed**. `SshPool.run()`'s output cap is now a single
  budget shared across stdout+stderr, so peak transient memory is `cap` not 2×cap.
- **EDGE-3 (P2)** — **Closed**. The edge Caddyfile proxies `/revoke` before the
  CIDR gate so a remote OAuth client can self-revoke a leaked token (the provider
  advertises `revocation_endpoint`; RFC 7009 makes public reachability safe).
- **EVID-1 (P2)** — **Closed** (follow-up). The audit-evidence verifier now
  orders retained segments by the first record's `ts` (chain-authoritative,
  immune to the logrotate `delaycompress` mtime inversion) via a two-phase
  `verify_segment()` restructure, and tolerates a single torn trailing record on
  the live segment (`torn_tails` counter). Removes the spurious "broken rotation
  seam" / "invalid JSON" false failures that silently suppressed the off-host
  sync (the anti-tail-truncation control, ADR 0007). 4 verifier tests.
- **PERF-4 (P2)** — **Closed** (follow-up). The single-host exec paths bound the
  output buffered in relay memory to `max_output_hard` (`shelltools._drive`'s
  bounded concurrent drain; `ssh_exec` passes `max_output_bytes`) instead of
  buffering the whole child output before truncating — a memory DoS reachable by
  a Tier-1 command `guarded` mode permits. Returned output byte-identical; child
  runs to completion. 7 tests. (Raised from info to P2/MED on review — it crosses
  the `guarded` boundary.) A later audit pass found the original PERF-4 fix
  missed two other single-host exec call sites: `ssh_keyscan`'s `run_command()`
  call and `ssh_check`'s `SshPool.run()` call both still passed no cap
  (`output_cap`/`max_output_bytes` unset, `cap is None`). `ssh_check` is Tier 0
  (permitted even in `readonly` mode) and both take a caller-chosen `hosts`
  argument, so this was a wider gap than the original: a malicious or
  compromised remote sshd could stream unbounded data back regardless of mode.
  Both now bound to a cap (`max_output_hard` for `ssh_keyscan`, a 4 KiB
  `_SSH_CHECK_PER_HOST_OUTPUT_CAP` for `ssh_check`'s substring-only probe).

### 7.3 Operations + observability

(B-014 closed by PR #47 — `RELAY_SHELL_AUDIT_FORMAT` shipped with
`jsonl`/`cef`/`leef` formatters in `src/relay_shell/audit.py`.)

- **AUD-1 (L2, P2)** — **Closed** as a split disposition (see `BACKLOG.md`).
  Evaluated the "in-band audit verify/correlate" lesson against ADR 0007 and the
  audit schema: **shipped** read-only triage filters on `audit_tail`
  (`tool`/`tier`/`denied`) for the operator-diagnostic case; **declined**
  in-band chain-verify (stays the CLI `--verify-audit`, ADR 0007 — the audited
  model must not drive verification of its own trail); correlate-by-input-hash is
  **N/A** (relay-shell hashes output, not input).
- **OPS-2 (L4, P3)** — layer KEV/EPSS exploit-prioritization signal on top of
  the existing `pip-audit` gate (advisory only; `pip-audit` already fails
  closed). Low value for the small pinned set; revisit if it grows.
- **PERF-1/2/3 (P3, low)** — deferred from the 2026-07-15 adversarial+perf pass
  (`BACKLOG.md`), none on a measured hot path: the synchronous audit
  write+flush on the event loop (offload like the read path only if a slow sink
  appears); `SshPool._sweep_conns` O(n)-under-lock per connect; and
  `Session.buffer` `bytearray` front-deletion. The hot-path redaction/classify
  costs from that pass (RED-6a/P1/POL-2 ReDoS + the unbounded scan) were
  **fixed** in the pass PR — see
  [`audit/2026-07-15-adversarial-engagement.md`](https://github.com/rmednitzer/relay-shell/blob/main/audit/2026-07-15-adversarial-engagement.md).

### 7.4 Docs and contribution

- **DOC-6 (L3, P2)** — **Closed**. `docs/deployment.md` §3a "Host integrity +
  config-drift monitoring" documents deploy-host file-integrity + config-drift
  monitoring (etckeeper / AIDE / fail2ban / lynis) as detection compensating for
  the intentionally-partial systemd confinement (ADR 0002). Lesson from the
  2026-07-15 Vertex/Axiom comparison; in scope per the CLAUDE.md GitHub checklist
  ("docs clearly explain secure deployment"). Docs only.
- **ENV-1 (P3, XS)** — **Closed** (PR #129). Added `RELAY_SHELL_CONFIRM_TIER3` /
  `RELAY_SHELL_CONFIRM_TTL` to `.env.example` (mirroring `Settings` +
  `docs/deployment.md` §8a); the 2026-07-15 session was blocked from editing
  `.env*` paths, so it landed as a follow-up.

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
  `sshpool.py` spawns no local child of its own,
  so there is nothing local to observe on that path; if a local-subprocess
  proxy path ever lands, the ambient-monitor pattern covers it the same way.
  Correction (2026-10-14, A14-RS): asyncssh does honour `ProxyCommand` and
  `Match exec` from the operator's `ssh_config`, which start a local process
  that this channel does not observe; the caller-supplied host, user and jump
  values that reach those tokens are now validated (runbook §3.2, `sshpool.py`).
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
  classifier, so a host name embedding a destructive word at a token start
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
  pack's deferred **P2-3**), and **required_status_checks** — exactly
  `check (py3.12)`, `check (py3.13)`, `check (py3.14)`, and
  `gitleaks (secret scan)` (the precise check-run names), all bound to
  GitHub Actions, strict=false. At that date pip-audit / dependency-review /
  CodeQL were advisory by operator choice (an upstream CVE disclosure must not
  block unrelated merges). `.github/workflows/ci-gate.yml` has since added a
  `ci-success` aggregate that waits for them too; whether `ci-success` is itself a
  required status in the ruleset is repository state not visible in-tree, so verify
  it with `GET /repos/rmednitzer/relay-shell/rules/branches/main`. Enumerated and applied via the operator's
  Vertex-held `gh` credential with explicit T3 confirmation; verified
  effective after the change via
  `GET /repos/rmednitzer/relay-shell/rules/branches/main`.
- **2026-06-21 full audit pass** — incremental hardening, no posture change.
  Full register in [`BACKLOG.md`](https://github.com/rmednitzer/relay-shell/blob/main/BACKLOG.md) (2026-06-21 section) and
  [`audit/2026-06-21-engagement.md`](https://github.com/rmednitzer/relay-shell/blob/main/audit/2026-06-21-engagement.md). Closed:
  SEC-3 (dependency floors) + TOOL-4 (CODEOWNERS → Renovate) in the pass PR;
  SEC-4 (Anthropic/HuggingFace redaction) in a follow-up; SEC-6 (refresh-token
  lock), SEC-7 (RFC 8707 `resource` forwarding), CI-1 (`release.yml`
  `persist-credentials`), CI-2 (`sbom.yml` interpolation + permissions) in the
  P2/P3 follow-up. **SEC-5** (`/metrics` auth) was accepted as-designed (operator decision
  2026-06-21: keep the default-`127.0.0.1` + Caddy-firewalled design rather than
  gating in-app, preserving the standard unauthenticated Prometheus-scrape
  model). **SEC-8** also closed in a follow-up: `_Store` creates the OAuth state dir
  `mode=0o700` and fails closed if it remains group/other-accessible (a
  correctly-`0o700` dir owned by another uid still passes). Remaining 2026-06-21
  items are info-only (**CI-3** / **DOC-5**) and out-of-scope **B-025**
  (aarch64); **FMT-2** closed in PR #111 (see §7.2 above); see `BACKLOG.md`.
- **2026-06-21 adversarial (red-team) pass** — incremental hardening, no
  posture change. Full register in [`BACKLOG.md`](https://github.com/rmednitzer/relay-shell/blob/main/BACKLOG.md) (2026-06-21
  adversarial section) and
  [`audit/2026-06-21-adversarial-engagement.md`](https://github.com/rmednitzer/relay-shell/blob/main/audit/2026-06-21-adversarial-engagement.md).
  The pass actively attacked the trust boundary with PoCs and found a systemic
  Python `\b` word-boundary bug that independently broke **two** controls.
  Closed in the engagement PR: **RED-1** (HIGH — compound `*_PASSWORD=` /
  `*_SECRET=` / `*_TOKEN=` secrets leaked to the audit log because `\b` never
  fired against a leading `_`; fixed by dropping the `\b`), **AUTH-1** (HIGH —
  `Bearer refresh:<tok>` authenticated as an access token; `load_access_token`
  now rejects the `refresh:` prefix), **POL-1** (MED — `>/dev/sda`, the fork
  bomb, `>/etc/` classified Tier 1 in `guarded`; `TIER2/TIER3` anchor `\b(` →
  `(?<![\w])(`), **RED-2** (MED — PEM-matcher ReDoS on the synchronous audit
  path; body length-bounded), and the two doc overclaims **DOC-1**
  (`SECURITY.md` keyless-chain / off-host caveat) and **DOC-2**
  (`docs/deployment.md` deny-list defence-in-depth + probe-format footgun).
  `PATTERNS_VERSION` 5→6. The MEDIUM/LOW deferrals (AUTH-2, SSH-1/2/3,
  SSRF-1, RED-3/4/5, CFG-1, OBS-1, DEP-1/2, EDGE-1/2) were all closed in follow-up PRs;
  their resolutions and the BY-DESIGN challenge results are in `BACKLOG.md`. No P0/critical, no
  remote-unauthenticated RCE, no auth-bypass-without-a-secret.

---

## 8. Documentation conventions

The per-file cross-checks that keep the Markdown consistent with the code. Label
numbers (8.9, 8.12a, 8.18, 8.20, 8.21, 8.23) are kept because ADRs and the changelog
cite them.

- **Capability tables.** The tool set in `README.md`, `docs/tools.md`, the server
  `_INSTRUCTIONS` and `tests/test_server.py::_EXPECTED` must agree (pinned by tests).
  Each tool's default-tier note must match `policy.py`; each "Tests:" line must name a
  file under `tests/`. The README status line must name the real version, Python
  matrix and a validation date that exists in ADR 0005.
- **Settings.** An added or removed `RELAY_SHELL_*` setting changes `Settings`,
  `.env.example` and `docs/deployment.md` together; `auth_*` settings also change
  `docs/auth.md` and `SECURITY.md`. The OAuth state files are `clients.json`,
  `approvals.json`, `codes.json`, `tokens.json`; list all four wherever state is described.
- **`SECURITY.md`.** Refresh the supported-versions table each release.
- **`CHANGELOG.md`.** Keep-a-Changelog; one block per category per release; cut
  `[Unreleased]` at release time.
- **8.9 ADR 0001 pin movement.** When `mcp` or `asyncssh` is bumped, add a one-line
  Consequences entry to ADR 0001 and sync the README compatibility matrix and
  `docs/architecture.md`.
- **8.12a ADR 0005 validation record.** Append a dated outcome paragraph and findings
  table per validation pass (file + line of each drift, the resolving PR); never overwrite
  an earlier date; refresh the ADR index subject.
- **8.18 ADR index.** `docs/adr/README.md` lists every ADR (number, title, status, date,
  one-line subject) and the next free number; a superseded ADR carries a `Superseded by`
  line.
- **8.20 Engagement packs.** `audit/<date>-engagement.md` is a frozen point-in-time
  record: never retro-edit a landed pack; add a new one per engagement; every fixed
  finding names its closing PR; findings left open reappear in the next pack.
- **8.21 `BACKLOG.md`.** The register of audit-pass deferrals. Add a row per deferred
  finding; close rows by naming the PR, never delete them. Ongoing queue items live in
  §7 here.
- **8.23 Docs site.** MkDocs Material from `docs/`, configured by `mkdocs.yml` (the `nav:`
  is the single navigation source; add a new guide to `nav:` and `docs/index.md`),
  published by `.github/workflows/docs.yml` with `mkdocs build --strict`. Pages must be
  set to the "GitHub Actions" source; the legacy `docs/_config.yml` can then be removed.
  Preview with `pip install -r requirements-docs.txt && mkdocs serve`.
- **Mirrored checklists.** If §3.1 or §3.3 of this runbook changes, mirror it in
  `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md`. The local loop in
  `CONTRIBUTING.md` must match §4.1.

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

## 10. OAuth resource binding migration

Bearer/resource validation is enabled explicitly. New authorization codes, access tokens and refresh tokens preserve the configured resource; code/refresh exchange uses the stored grant, never caller-supplied scopes or audience. The token endpoint also rejects explicit foreign or duplicate resource parameters, because the SDK token handler does not pass that field to the provider. Missing request parameters select this server's sole configured resource; missing stored bindings fail closed.

`RELAY_SHELL_AUTH_RESOURCE_URL` can name a separate public MCP resource. Empty preserves the existing issuer-based resource identifier so discovery identifiers do not silently change during upgrade. New deployments should set the exact public MCP endpoint. There is no automatic grandfathering or timed fail-open mode.

Existing local opaque grants may be reauthorized, or an operator may explicitly rebind them offline using `scripts/bind-legacy-oauth.py`. This is a policy migration, not recovery of historical audience evidence. The script defaults to dry-run and exposes counts/hashes only. Apply requires root, a stopped service, an exact token-store preimage hash, private state and backup paths, known registered clients and the existing `mcp:tools` scope. It refuses foreign bindings, preserves expiry and scopes, and writes a private preimage before atomic replacement. Never upload token stores or backups to source control.

Deploy from an independently supervised transaction with the previous complete runtime retained and an automatic rollback deadline. Synthetic registration/PKCE/refresh/wrong-resource tests precede cutover; verify an actual existing connector afterwards before cancelling rollback. A rollback selects the prior runtime but must not restore token-store snapshots over newer grants or audit records. Additive resource fields are ignored by the previous runtime. Do not change issuer/resource identifiers at the same time as this migration.
