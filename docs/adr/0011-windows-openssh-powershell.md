# ADR 0011: Windows targets via OpenSSH + PowerShell 7

- Status: Accepted
- Date: 2026-07-15

## Context

`relay-shell` was built and hardened against POSIX SSH targets. A concrete
deployment question — administering **Windows hosts over OpenSSH with
PowerShell 7 (`pwsh`) as the login/`DefaultShell`** — surfaced how much of the
stack silently assumes POSIX, and, more importantly, where that assumption is a
**safety** gap rather than a functional one.

A code audit (2026-07-15) mapped the current state. Two findings frame this ADR:

**Execution already works.** `SshPool.run` and `SshPool.open_process` pass the
raw command string straight to asyncssh's `conn.create_process(command)` — no
`/bin/sh -c` wrapping, no POSIX quoting, no `shlex`. asyncssh hands the string
to whatever the SSH server runs as its command interpreter, so with
`DefaultShell=pwsh` an `ssh_exec`/`ssh_spawn`/`ssh_fanout` command is
interpreted by PowerShell 7 with no adapter layer. SFTP paths pass through
opaquely (a caller can use `C:\...` or `/c/...` as the server expects). So
Windows/pwsh targets are already **functional** today.

**The classifier is blind to them — and that is the part that matters.** The
tier heuristics in `patterns.py` (`TIER3_PATTERN`, `TIER2_PATTERN`,
`PRIV_ESC_PATTERN`, consumed by `policy.classify`) are POSIX command-name
matches: `rm -rf`, `mkfs`, `shutdown`, `systemctl`, `sudo`. A PowerShell 7
target's destructive operations — `Remove-Item -Recurse -Force`, `Clear-Disk`,
`Format-Volume`, `Stop-Computer`, `Remove-Service`, `Remove-LocalUser`,
`vssadmin delete shadows` — classify as **Tier 1**. Consequences: `guarded`
mode does not refuse them, `readonly` mode's ceiling does not see them, and the
opt-in Tier-3 confirmation broker (ADR 0009) never fires. The compensating
controls that make the unsandboxed posture (ADR 0002) safe to operate are
**absent for the exact class of operation they exist to guard** on a Windows
target. This is the crux of the ADR; everything else is secondary polish.

PowerShell 7 also *simplifies* one concern the initial (cmd.exe-oriented)
analysis raised: `pwsh` defaults to **UTF-8** for its output stream, so the
existing hardcoded `decode("utf-8", "replace")` in `sshpool.py` / `sessions.py`
is correct for cmdlet output — the OEM-codepage mangling that afflicts
`cmd.exe` / Windows PowerShell 5.1 does not apply to the pwsh-7 path (a native
`.exe` invoked *from* pwsh can still emit OEM bytes; that is a documented edge,
not a feature to build).

## Decision

Adopt **Windows-over-OpenSSH-with-PowerShell-7 as a first-class target class**,
delivered as compensating-control and documentation work — not a new transport,
not a command/path translation layer. Scope is deliberately bounded to the
`pwsh` deployment; `cmd.exe` / Windows PowerShell 5.1 are out of scope except
where a native `.exe` reachable from `pwsh` is already covered.

This ADR records the decision and the plan; the increments land as their own
reviewed PRs. Increment **A** (classification) is the one that closes a safety
gap and is the reason this needs an ADR (it extends what the tier classifier
*means*, across a new shell surface — more than "another verb", see ADR-README
"when to write an ADR"); the rest are ordinary review-loop changes tracked here
for coherence.

### A. PowerShell-7-aware tier classification (the safety fix)

Extend `TIER3_PATTERN` / `TIER2_PATTERN` / `PRIV_ESC_PATTERN` with Windows/pwsh
alternatives, under the **same discipline as the POSIX rules**: `(?<![\w])`
anchoring, bounded quantifiers (no catastrophic backtracking — the RED-7/POL-2
ReDoS ceiling tests apply), paired positive **and** negative (false-positive)
tests, and a `PATTERNS_VERSION` bump. POSIX matching stays byte-identical
(pure additions).

- **Tier 3 (irreversible):** `Remove-Item … -Recurse`/`-Force` (and the aliases
  `del`/`ri`/`rd`/`rmdir`/`erase`; note `rm -Recurse` already trips the existing
  `rm\s+-[rf]` rule via case-insensitivity), `Clear-Disk`, `Format-Volume`,
  `Initialize-Disk`, `Stop-Computer`/`Restart-Computer`, `Remove-Service`,
  `Remove-LocalUser`/`Remove-LocalGroup`, `Clear-EventLog`, plus native
  destructive `.exe`s still reachable from `pwsh` (`diskpart`, `format`,
  `vssadmin delete shadows`, `bcdedit`, `cipher /w`, `reg delete`).
- **Tier 2 (stateful):** `Stop-Service`/`Set-Service`,
  `Install-Module`/`Install-Package`/`Uninstall-*`,
  `Remove-`/`Disable-`/`Set-NetFirewallRule`, `Set-ItemProperty … HKLM:`,
  `Register-`/`Unregister-ScheduledTask`, `New-LocalUser`.
- **Privilege escalation / high-risk:** add `runas` and
  `Start-Process … -Verb RunAs` to `PRIV_ESC_PATTERN` (Windows 11's native
  `sudo` is already the `sudo` token the rule matches). Consider
  `Invoke-Expression`/`iex` and `Set-ExecutionPolicy` as security-relevant.

The cmdlet names are distinctive CapCase-hyphenated tokens, so false-positive
risk is low (unlike the short `cmd.exe` verbs `del`/`rd`/`sc`, which the pwsh
scope lets us avoid centering on).

### B. Documentation

A `docs/deployment.md` (+ the `_OPERATING_GUIDE` prompt) section on
Windows/pwsh-7 targets: what already works (native-shell execution, SFTP), that
the classifier now covers common pwsh destructive cmdlets, the honest limits
below, and the native-`.exe` UTF-8 caveat.

### C. Redaction (small follow-up)

Add `credential` and `asplaintext` to the CLI-flag redaction keyword list so
`-Credential` and `ConvertTo-SecureString -AsPlainText '…'` do not reach the
audit log ( `-Password`/`-Token`/`-ApiKey` are already caught by the single-dash
`--?` rule). Document the residue the audit found (positional secrets like
`net user <name> <pass>` remain unredactable — a POSIX-shared limitation).

### D / E. Encoding and PTY (documented caveats, not features)

- **Encoding:** none needed for the pwsh-7 path (UTF-8 by default). Document the
  native-`.exe`-OEM edge; only revisit with a config/inventory-field if a mixed
  fleet demands it.
- **PTY:** `term_type` is hardcoded `xterm-256color`; make it overridable if a
  need appears, and document that the SSH `signal` request (used by
  `session_kill`) may be a no-op on older Windows OpenSSH builds, degrading to
  best-effort `terminate()`. Modern OpenSSH + pwsh-7 largely handle ConPTY and
  window-change.

### What this decision explicitly does NOT do

- **No command or path translation** between POSIX and Windows. The remote
  `pwsh` interprets the command; the caller supplies pwsh-appropriate syntax.
  An adapter layer would be a large, brittle surface for no capability gain
  (ADR 0002 preserves operator power; this adds visibility, not translation).
- **No PowerShell interpreter for the *local* `shell_script`.** That tool spawns
  a local subprocess and is a separate, local-OS axis; it is untouched.
- **No new transport, tool, or auth provider.** This is classification +
  redaction + docs on the existing SSH path; the tool contract count is
  unchanged.

## Consequences

- **Sequencing.** A + B ship first as one PR (the safety fix plus honest docs);
  C is a small follow-up; D/E are documentation caveats that ride B. Each
  through the normal review loop; A is `patterns.py`-touching, so it is
  security-sensitive (runbook §3.3) and gets a redaction/classification review
  and the ReDoS-ceiling tests.
- **`PATTERNS_VERSION` bumps** once for increment A (audit consumers can detect
  the widened classification surface, per the module's version contract).
- **Classification remains heuristic — sharper caveat for PowerShell.** pwsh
  parameters are case-insensitive, abbreviatable (`-Recurse` → `-rec` → `-r`),
  and `:`-bindable (`-Recurse:$true`), and cmdlets have aliases. Matching a
  cmdlet by name is reliable; a fully-abbreviated-alias form (`ri -rec -fo`) or
  an obfuscated pipeline can still evade it — exactly the ADR 0003
  "heuristic, advisory, defence-in-depth" property, now stated for Windows too.
  The deny list and `guarded`/`readonly` remain the hard controls; this widens
  the guardrail, it does not make it a sandbox.
- **Trust boundary unchanged.** Like ADR 0006/0009 this adds compensating
  controls layered on ADR 0003 classification; it does not move the ADR 0002
  boundary, and (as always) the tier gate never overrides the deny list.
- Tracked as backlog item **WIN-1** (runbook §7.1), which points here.

## Rejected alternatives

- **Do nothing / treat Windows as unsupported.** Functionally it already works,
  so "unsupported" would be untrue *and* leave the classifier blind on live
  Windows admin — the worst combination (operators get the capability with none
  of the guardrail). Rejected.
- **A command/path translation / normalization layer** (rewrite POSIX ⇄ pwsh,
  normalize path separators). Large, brittle, and unnecessary: the remote shell
  already interprets its own syntax. It would add surface and bugs for zero
  capability gain. Rejected in favor of classify-and-audit-what-is-sent.
- **A global remote-output-encoding setting now.** Solved a problem the pwsh-7
  path does not have (pwsh is UTF-8). A global setting is also wrong for a mixed
  Linux+Windows fleet. Deferred to a per-host inventory field *if* a concrete
  mixed-fleet, native-`.exe`-heavy need appears. Rejected for now.
- **Fold Windows verbs into the deny list instead of the tier patterns.** The
  deny list is deployment-specific and absolute; classification is the general,
  shipped-default guardrail that feeds `guarded`/`readonly`/the broker. Windows
  destructive operations belong in the same shipped classifier as their POSIX
  peers, not offloaded to every operator's deny regex. Rejected.

## Validation outcome (2026-07-15)

Increments **A** (classification) and **B** (docs) implemented in the PR that
moves this ADR to Accepted:

- `patterns.py` — `TIER3_PATTERN` / `TIER2_PATTERN` / `PRIV_ESC_PATTERN` gained
  the Windows/pwsh alternatives above as pure additions; `PATTERNS_VERSION`
  9 → 10. The bounded-gap rules (`Remove-Item … -Recurse`, `del … /s`,
  `format … <drive>`) use the RED-7 `{0,N}?` ReDoS ceiling.
- Tests (`tests/test_patterns.py`): paired positive / negative cases for the
  Tier-3, Tier-2, and priv-esc additions (the negatives pin no over-classification
  of `Format-Table`, `Get-ChildItem -Recurse`, a single-file `Remove-Item`, prose
  `format`, and read-only `Get-*` counterparts), plus a ReDoS-ceiling test on a
  large verb-repeating argument. POSIX classification verified byte-identical (the
  existing `test_policy.py` / `test_patterns.py` POSIX cases pass unchanged).
- Docs (`docs/deployment.md` §8b): what already works, the newly-classified
  operations, the heuristic caveat (pwsh abbreviation / aliases / pipeline
  forms), the UTF-8 / native-`.exe` encoding edge, and the ConPTY / `session_kill`
  signal note.

Increment **C** (`-Credential` / `-AsPlainText` redaction) remains a small
follow-up (runbook §7.1, WIN-1); increments **D** (encoding) and **E** (PTY)
stay documented caveats, not features, per the decision above. No change to the
tool contract, transport surface, audit-record shape, or the ADR 0002/0003 trust
boundary.
