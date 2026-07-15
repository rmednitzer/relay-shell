"""Compiled, version-pinned regex tables for the redaction and policy layers.

This module exists so that "added a pattern" is a one-file diff: a security
reviewer auditing redaction or tier classification can read the tables here
without scrolling past the executor in :mod:`relay_shell.redaction` or
:mod:`relay_shell.policy`.

Three pattern families are exported:

* :data:`REDACTION_PREFIX_PATTERNS` - structure-preserving redactions: keep
  the non-secret prefix, replace the value with :data:`REDACTION_PLACEHOLDER`.
* :data:`REDACTION_PATTERNS` - whole-match redactions: the entire match
  collapses to :data:`REDACTION_PLACEHOLDER`.
* :data:`TIER2_PATTERN`, :data:`TIER3_PATTERN`, :data:`PRIV_ESC_PATTERN` -
  tier-classification heuristics consumed by :func:`relay_shell.policy.classify`.

Two further patterns serve the MySQL-family special case in redaction:
:data:`MYSQL_FAMILY_CLI_PATTERN` gates the application of
:data:`MYSQL_COMPACT_PASSWORD_PATTERN` to ``-p<value>`` short-form passwords
only when a MySQL CLI appears in the argument string. :data:`URL_CREDS_PATTERN`
handles ``://user:pass@host`` URL embeddings.

:data:`PATTERNS_VERSION` is a monotonic counter. Bump it on any semantic
change to a pattern (added, widened, narrowed, or removed). Audit consumers
can read the version off the module to detect an upgrade in the
classification or redaction surface.
"""

from __future__ import annotations

import re

__all__ = [
    "MYSQL_COMPACT_PASSWORD_PATTERN",
    "MYSQL_FAMILY_CLI_PATTERN",
    "PATTERNS_VERSION",
    "PRIV_ESC_PATTERN",
    "REDACTION_PATTERNS",
    "REDACTION_PLACEHOLDER",
    "REDACTION_PREFIX_PATTERNS",
    "TIER2_PATTERN",
    "TIER3_PATTERN",
    "URL_CREDS_PATTERN",
]

# Bump on any semantic change to a pattern (added / widened / narrowed /
# removed). v1: initial extraction from redaction.py + policy.py.
# v2: Authorization-header value widened to handle three shapes (bare
#     HTTP, quoted CLI flag, JSON dict literal) and to consume past the
#     first comma so AWS SigV4 / Digest challenge-response schemes do
#     not leak the trailing Signature/response field.
# v3: Authorization-header bare form no longer consumes arbitrary shell
#     control operators; this preserves audit fidelity for command-style
#     input while keeping quoted/JSON and comma-separated auth schemes.
# v4: REDACTION_PATTERNS gained the common structurally-anchored provider
#     secret shapes that the prefix patterns miss when a secret arrives
#     bare (in a JSON body, a log line, or a flag not in the CLI list):
#     Google API key (AIza), Google OAuth access token (ya29.), Stripe
#     secret/restricted keys (sk_/rk_ live/test/prod), GitLab PAT
#     (glpat-), npm token (npm_), PyPI upload token (pypi-AgE...), and
#     JWTs (ey<hdr>.ey<payload>.<sig>). The OpenAI `sk-` shape was
#     widened to also cover the project/service prefixes
#     (sk-proj-/sk-svcacct-/sk-admin-, with URL-safe tails). Anchors track
#     the canonical secret-scanning rulesets (gitleaks / GitHub secret
#     scanning); every body runs unbounded from its length floor and admits
#     the token's full alphabet (ya29 dots, OpenAI URL-safe separators) so a
#     match always collapses the *whole* token rather than leaving a tail.
# v5: REDACTION_PATTERNS gained Anthropic API keys (`sk-ant-...`) and
#     HuggingFace user access tokens (`hf_...`) — both high-likelihood in an
#     AI-infrastructure tool's command arguments and previously uncovered (the
#     `sk-ant-` hyphens break the bare `sk-<alnum>` run; `hf_` had no rule).
#     Whole-match collapses anchored on prefix + length floor like the rest
#     (audit pass 2026-06-21, SEC-4).
# v6: adversarial-audit fixes (2026-06-21 red-team pass).
#     - The `key=value` redaction prefix no longer requires a leading `\b`:
#       in compound names (`DB_PASSWORD=`, `APP_SECRET=`, `API_TOKEN=`) the
#       keyword is preceded by `_` (a word char) so `\b` never fired and the
#       value leaked to the audit log (RED-1). The trailing `\s*[:=]\s*\S+`
#       still gates it to assignment shapes, so removing `\b` does not
#       over-match plain words.
#     - TIER2/TIER3 classification anchors switched from `\b` to `(?<![\w])`
#       so the alternatives that start with a non-word char (`>`/`/`/`:` —
#       device-write redirects, `>/etc/`, the fork bomb) actually fire instead
#       of being dead code (POL-1).
#     - The PEM block matcher's `.*?` is now length-bounded to stop O(n²)
#       backtracking on many unterminated BEGIN markers (ReDoS on the audit
#       path, RED-2).
# v7: redaction coverage additions (2026-06-21 adversarial follow-up, RED-3).
#     New structure-preserving prefixes: AWS `*_SECRET_ACCESS_KEY=` (the
#     keyword is mid-name, so the generic `secret=` rule never fired —
#     anchored on the full `secret_access_key` phrase for FP control); Azure
#     connection-string `AccountKey=` / `SharedAccessKey=`; and Azure SAS
#     `?…&sig=<urlencoded>`. New whole-match: Slack incoming-webhook URLs
#     (`https://hooks.slack.com/services/T…/B…/…`; distinct from the `xox*`
#     token rule). GCP service-account creds need no new rule — their only
#     secret is the `private_key` PEM block, already collapsed by the PEM rule
#     above (it matches a JSON-embedded block with escaped `\n` too).
# v8: 2026-07-15 adversarial pass. RED-6: the generic keyword rule and the AWS
#     `secret_access_key` rule gained a quote-tolerant separator (`["']?` each
#     side) + a quoted-value terminator, so the JSON-quoted-key shape
#     (`"password": "x"`, `"AWS_SECRET_ACCESS_KEY": "x"`) is redacted — it was
#     leaking verbatim to the audit log (only the Authorization rule had been
#     quote-tolerant). Unquoted cases stay byte-identical (the `\S+` fallback).
#     RED-7: TIER3_PATTERN gained a long-option `rm` alternative
#     (`rm --recursive|--force|--no-preserve-root`); the short-flag-only
#     alternatives under-classified `rm --force` below Tier 3.
# v9: 2026-07-15 redaction review. RED-8: the CLI-flag rule's quoted-value
#     branches (`--password="..."` / `'...'`) required a closing quote and were
#     length-unbounded, so a quoted secret longer than the redaction scan window
#     (`_scrub_str`'s `max_len + 16 KiB`) lost its closing quote to truncation:
#     the quoted branch could not match and the greedy bare fallback stopped at
#     the first internal space, leaking the value's tail into the length-bounded
#     audit record (a P1 scan-window regression; full-string redaction still
#     caught it). Added unterminated-quote fallback branches that consume to
#     end-of-line, so a truncated/malformed quoted value still collapses whole.
#     Well-formed quoted values are byte-identical (the terminated branch is
#     tried first).
# v10: 2026-07-15 Windows/PowerShell-7 support (ADR 0011, WIN-1). TIER3_PATTERN /
#      TIER2_PATTERN / PRIV_ESC_PATTERN gained Windows + pwsh alternatives so
#      destructive PowerShell cmdlets and cmd.exe verbs on a Windows OpenSSH
#      target classify at the right tier instead of falling through to Tier 1
#      (which escaped `guarded`/`readonly` mode and the ADR 0009 broker). Pure
#      additions — POSIX matching is byte-identical; the bounded-gap rules
#      (`Remove-Item … -Recurse`, `del … /s`, `format … C:`) mirror the RED-7
#      `{0,N}?` ReDoS ceiling. Classification stays heuristic: PowerShell
#      parameter abbreviation / aliases / pipeline-delete forms can still evade
#      it (documented in ADR 0011), so the deny list + modes remain the hard
#      controls.
# v11: 2026-07-15 Windows/pwsh redaction (ADR 0011 increment C, WIN-1). Added
#      `credential` to the generic keyword rule and the CLI-flag rule (covers
#      `-Credential x`, `credential=x`, `"credential":"x"`), and a dedicated
#      `ConvertTo-SecureString` rule that redacts an inline plaintext operand
#      (`ConvertTo-SecureString 'P@ss' -AsPlainText -Force`) while leaving a
#      `$var` handle or a bare switch untouched. Keeps existing keyword behavior
#      byte-identical (pure additions).
PATTERNS_VERSION = "11"

REDACTION_PLACEHOLDER = "[REDACTED]"


# --- Redaction: structure-preserving (keep the prefix, replace the value) ---

REDACTION_PREFIX_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization / Proxy-Authorization header value. Handles three
    # input shapes the relay actually sees:
    #
    #   1. Bare HTTP header  ->  `Authorization: Bearer X`
    #      Value runs until a line break or shell control operator.
    #   2. Quoted CLI flag    ->  `-H "Authorization: Bearer X"`
    #      Value stops at the surrounding closing quote.
    #   3. JSON dict literal  ->  `{"Authorization": "Bearer X"}`
    #      Key and value are each independently quoted; the optional
    #      `["']?` in the prefix lets us match the quote-colon-quote
    #      transition and the value runs to the closing inner quote.
    #
    # The terminator set deliberately excludes `,`: AWS Signature v4
    # (`Credential=..., SignedHeaders=..., Signature=<hex>`) and other
    # comma-separated challenge-response schemes put the actual secret
    # (the Signature) AFTER a comma. Stopping at the first comma would
    # leak it. The trade-off is that an inline `Authorization: ...,
    # otherfield=val` will over-scrub `otherfield=val` - that case is
    # uncommon and the over-scrub is audit-fidelity loss, not a leak.
    (
        re.compile(
            r"(?i)\b(?P<prefix>(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?)"
            r"(?:"
            r"[^\"'\r\n]+(?=[\"'])"
            r"|[^\r\n\"']+?(?=(?:\s(?:&&|\|\||\|)\s|[\r\n]|$))"
            r")"
        ),
        r"\g<prefix>[REDACTED]",
    ),
    # Bearer <token>
    (
        re.compile(r"(?i)\b(?P<prefix>bearer\s+)[A-Za-z0-9._\-]+"),
        r"\g<prefix>[REDACTED]",
    ),
    # token=... / api[_-]?key=... / password: ...  (also the JSON-quoted-key
    # shape `"password": "x"`). The separator tolerates an optional quote on
    # either side (`["']?`), mirroring the Authorization rule, so a JSON key
    # like `"password"` (a `"` sits between the keyword and the `:`) still
    # anchors — RED-6. The value has two branches: a quoted value stops at its
    # closing quote (so the trailing `",` / `"}` is preserved), otherwise the
    # historical `\S+` (stop at whitespace) is used unchanged, so every
    # pre-RED-6 unquoted case redacts byte-identically.
    (
        re.compile(
            r"(?i)(?P<prefix>(?:api[_-]?key|secret|token|password|passwd|pwd|credential)"
            r"[\"']?\s*[:=]\s*[\"']?)"
            # Value = non-space, non-quote run. Stopping at a quote catches the
            # JSON-quoted-key shape `"password": "x"` (the value ends at the
            # closing quote, which is preserved) while keeping the historical
            # single-token behaviour for the unquoted `password=x` / `token: x`
            # forms (RED-6). A single greedy char-class `+` with nothing after it
            # cannot backtrack, so this is strictly linear — unlike a
            # `[^"'\r\n]+(?=["'])` lookahead form, which is O(n²) when the prefix
            # recurs across a large quote-free argument (a ReDoS on the sync
            # audit path).
            r"[^\s\"'\r\n]+"
        ),
        r"\g<prefix>[REDACTED]",
    ),
    # AWS secret access key assignment (RED-3). The `secret` keyword sits
    # mid-name in `AWS_SECRET_ACCESS_KEY=`, so the generic `secret=` rule above
    # never fires (`secret` is followed by `_ACCESS_KEY`, not `=`). Anchor on
    # the full `secret[_-]?access[_-]?key` phrase — distinctive enough that
    # `SECRET_ACCESS_KEY_PATH=/x` (the `_PATH` breaks the `key[:=]` adjacency)
    # and similar are not over-scrubbed. Quote-tolerant separator + quoted-value
    # terminator like the generic rule above, so the JSON-quoted-key shape
    # `"AWS_SECRET_ACCESS_KEY": "x"` is caught (RED-6); the AWS secret has no
    # whole-match fallback, so this prefix rule is the only thing protecting it.
    (
        re.compile(
            r"(?i)(?P<prefix>(?:aws[_-]?)?secret[_-]?access[_-]?key"
            r"[\"']?\s*[:=]\s*[\"']?)"
            # Non-space, non-quote value run — quote-aware and linear, same as
            # the generic rule above (RED-6).
            r"[^\s\"'\r\n]+"
        ),
        r"\g<prefix>[REDACTED]",
    ),
    # Azure connection-string keys (RED-3): `AccountKey=<base64>` (Storage) and
    # `SharedAccessKey=<base64>` (Service Bus / Event Hubs). The value runs to
    # the `;` segment separator (or whitespace/quote), so the rest of the
    # connection string is preserved for the audit reader.
    (
        re.compile(r"(?i)(?P<prefix>(?:account|sharedaccess)key\s*=\s*)[^;\s\"']+"),
        r"\g<prefix>[REDACTED]",
    ),
    # Azure SAS token signature (RED-3): the `sig=` query parameter carries the
    # HMAC signature that authorizes the URL. Anchored on a leading `?`/`&` so
    # `design=`/`sign=` substrings cannot match, and on a 20+ char url-encoded
    # base64 body so a tiny unrelated `sig=` is left alone.
    (
        re.compile(r"(?i)(?P<prefix>[?&]sig=)[A-Za-z0-9%/+]{20,}"),
        r"\g<prefix>[REDACTED]",
    ),
    # CLI-style flags: ``--password value``, ``--token=value``,
    # ``--api-key "two words"``, ``--password top\ secret``. See the
    # docstring of :mod:`relay_shell.redaction` for scope and the reasoning
    # around interactive flags / dash-prefixed values.
    #
    # The leading ``(?<![A-Za-z])`` keeps the dash from binding to the tail of a
    # PowerShell ``Verb-Noun`` cmdlet: ``Get-Credential`` / ``Get-Secret`` /
    # ``Remove-Secret`` contain ``-Credential`` / ``-Secret`` but take no inline
    # secret, and without the guard the rule would over-scrub the *next* token
    # (`-Message`, a task name, …). A real secret flag is preceded by
    # whitespace / start / ``=`` / a quote — never a letter — so the guard never
    # reduces true redaction (WIN-1 / ADR 0011 increment C).
    (
        re.compile(
            r"""(?ix)
            (?P<prefix>
                (?<![A-Za-z])
                --?(?:password|passwd|pwd|secret|token|api[_-]?key|credential)
                [=\ \t]+
            )
            (?:
                "(?:[^"\\]|\\.)*"        # double-quoted, escape-aware
              | '(?:[^'\\]|\\.)*'        # single-quoted, escape-aware
              | "[^\r\n]*                # RED-8: unterminated double-quote — the
                                        # closing quote is missing (a malformed arg)
                                        # or truncated out of the redaction scan
                                        # window (_scrub_str). Consume to end-of-line
                                        # so a long quoted secret whose close quote
                                        # falls past the window is still collapsed
                                        # instead of leaking its post-space tail.
                                        # Tried only after the terminated branch
                                        # above fails, so well-formed values are
                                        # byte-identical; audit-fidelity-loss (not a
                                        # leak) in the genuinely-unterminated case,
                                        # matching the Authorization rule's tradeoff.
              | '[^\r\n]*                # unterminated single-quote (as above)
              | (?:-(?!-)|(?!--))(?:\\.|\S)+
                                        # bare value, treating \\<char> as one unit;
                                        # allow single-dash-prefixed secrets (-abc)
                                        # but still reject next long option (--host)
            )
            """,
        ),
        r"\g<prefix>[REDACTED]",
    ),
    # PowerShell inline plaintext via ``ConvertTo-SecureString`` (WIN-1 / ADR
    # 0011 increment C). The canonical pwsh idiom for putting a secret on the
    # command line:
    #   ConvertTo-SecureString 'P@ss' -AsPlainText -Force
    #   ConvertTo-SecureString -String "P@ss" -AsPlainText
    # Redact the operand so the plaintext never reaches the audit log. The
    # bounded ``(?:-\w+\s+){0,8}?`` skips any leading switches (`-AsPlainText`,
    # `-Force`, `-String`) — bounded like the RED-7 rules so it stays linear —
    # then the operand is a quoted string OR a bare non-flag/non-variable token.
    # Requiring ``(?![-$])`` on the bare branch means a switch or a `$var`
    # (an already-encrypted handle, not plaintext) is never over-scrubbed; only
    # an inline literal secret is collapsed.
    (
        re.compile(
            r"""(?ix)
            (?P<prefix>convertto-securestring\s+(?:-\w+\s+){0,8}?)
            (?:
                "(?:[^"\\]|\\.)*"          # double-quoted secret
              | '(?:[^'\\]|\\.)*'          # single-quoted secret
              | (?![-$])\S+                # bare literal (not a switch, not a $var)
            )
            """,
        ),
        r"\g<prefix>[REDACTED]",
    ),
)


# --- Redaction: whole-match (collapse the entire match to the placeholder) ---

# Provider token shapes are *structurally* anchored (a fixed prefix and a
# length floor), not anchored on the secret's character class - the
# character class evolves, the structure does not (see the redaction
# module docstring and runbook §6.5). Anchors and length bounds track the
# canonical secret-scanning rulesets so this set stays comparable to what
# gitleaks / GitHub secret scanning detect:
#   https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
# These run as whole-match collapses: a provider token has no useful
# non-secret prefix to preserve, so the entire match becomes the
# placeholder. They are the safety net for secrets that arrive *bare* -
# in a JSON body, a log line, or a flag the CLI-flag prefix patterns do
# not name - which the prefix patterns alone would miss.
REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PEM / OpenSSH private key blocks
    re.compile(
        # Length-bound the body (a real PEM key block is < ~8 KB) so a large
        # argument carrying many unterminated `-----BEGIN ... KEY-----` markers
        # cannot drive O(n^2) backtracking and stall the (synchronous) audit
        # redaction path. `[\s\S]` spans newlines without needing DOTALL.
        r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]{0,8192}?"
        r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----",
    ),
    # GitHub: classic/fine-grained PAT, plus the gh[pousr]_ token family
    # (personal, OAuth, user-to-server, server-to-server, refresh).
    re.compile(r"\bgith(?:ub)?_pat_[A-Za-z0-9_]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    # OpenAI keys. Two rules by design: the classic `sk-<alnum>` body is
    # kept narrow (alphanumeric only) so kebab-case identifiers such as
    # `sk-build-step` are not over-scrubbed; the project / service-account
    # / admin formats carry URL-safe opaque tails that legitimately contain
    # `_` and `-`, so their body admits those separators and runs unbounded
    # — otherwise the redactor would stop at the first separator and leave
    # the remainder of the key in the audit log.
    re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    # Anthropic API key (`sk-ant-<acct-type><nn>-<body>`). The `sk-ant-`
    # hyphens break the bare `sk-<alnum>` run above, so it needs its own rule;
    # the opaque body admits URL-safe `_`/`-` and runs unbounded from the floor
    # so the whole key collapses rather than stopping at the first separator.
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    # HuggingFace user access token (`hf_` + >=34 alnum body).
    re.compile(r"\bhf_[A-Za-z0-9]{34,}"),
    # AWS access key id (fixed-length AKIA + 16).
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Slack token family (bot/user/app/refresh/legacy).
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    # Slack incoming-webhook URL (RED-3): the full URL is the credential —
    # anyone holding it can post to the channel. Distinct from the `xox*`
    # token rule above. Collapses the whole URL.
    re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
    # Google API key (AIza + 35) and OAuth 2.0 access token (ya29.<...>).
    # Both run unbounded from the length floor so the whole token collapses
    # rather than leaving a tail. The ya29 body admits `.`: these access
    # tokens are opaque and carry additional dots, so stopping at the first
    # one would strand the remainder of the credential.
    re.compile(r"\bAIza[A-Za-z0-9_\-]{35,}"),
    re.compile(r"\bya29\.[A-Za-z0-9._\-]{20,}"),
    # Stripe secret (sk_) and restricted (rk_) keys, test/live/prod.
    # Unbounded body so a longer (future) key collapses whole.
    re.compile(r"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,}"),
    # GitLab personal/project/group access token.
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    # npm automation/access token (>=36-char body, unbounded so a longer
    # token collapses whole instead of failing a fixed-length boundary).
    re.compile(r"\bnpm_[A-Za-z0-9]{36,}"),
    # PyPI upload token (the AgEIcHlwaS5vcmc macaroon header is base64 of
    # "pypi.org" and is a near-unique structural anchor).
    re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{16,}"),
    # JSON Web Token: two `ey...` base64url segments (the JWT header and
    # payload both begin `{"`, which base64url-encodes to `ey`) plus an
    # optional signature segment. The header floor stays high (a real JWT
    # header is always >=17 chars) as the strong anchor against false
    # positives, while the payload / signature floors are low so a *compact*
    # JWT with a small claim set (e.g. `{"sub":"1"}`) is still redacted.
    # Bearer-prefixed JWTs are already caught by REDACTION_PREFIX_PATTERNS;
    # this collapses a bare JWT (an id_token in a JSON body, an --jwt-style
    # flag the prefix list does not name).
    re.compile(r"\bey[A-Za-z0-9_\-]{17,}\.ey[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]{8,})?"),
)


# --- Redaction: URL-embedded credentials (structure-preserving) ---

URL_CREDS_PATTERN = re.compile(r"://[^/\s:@]+:[^/\s:@]+@")


# --- Redaction: MySQL-family compact -p<value> (gated by family CLI) ---

MYSQL_FAMILY_CLI_PATTERN = re.compile(r"\b(?:mysql\w*|mariadb\w*|mycli)\b", re.IGNORECASE)
MYSQL_COMPACT_PASSWORD_PATTERN = re.compile(r"(?<![A-Za-z0-9-])(-p)[^\s=-]\S*")


# --- Policy: tier classification heuristics ---

# Substrings that strongly imply an irreversible / high-blast action.
TIER3_PATTERN = re.compile(
    r"(?ix)(?<![\w])("
    r"rm\s+-[rf]|rm\s+-[a-z]*f|"
    # Long-option `rm` (RED-7): `rm --recursive`, `rm --force`,
    # `rm --no-preserve-root`, and mixed forms (`rm -r --force`, `rm file
    # --force`) — the short-flag alternatives above require a single dash
    # immediately after `rm `, so a `--`-flag slipped past them and
    # under-classified a genuinely destructive command below Tier 3. The
    # intervening-token count is BOUNDED (`{0,16}?`, disjoint \S/\s): a real
    # rm has few flags before the destructive one, and an unbounded `*?` would
    # be O(n^2) on `rm rm rm …` (classify retries every `rm ` position) — a
    # ReDoS on the synchronous admission path.
    r"rm\s+(?:\S+\s+){0,16}?--(?:recursive|force|no-preserve-root)\b|"
    r"shred|mkfs|fdisk|sgdisk|wipefs|"
    r"dd\s+[^|]*of=/dev/|>\s*/dev/[sh]d|"
    r"shutdown|reboot|halt|poweroff|init\s+0|init\s+6|"
    r"drop\s+database|drop\s+table|truncate\s+table|"
    r"git\s+push\s+.*--force|git\s+reset\s+--hard|"
    r"userdel|deluser|gpasswd|passwd\s+|"
    r"iptables\s+-F|nft\s+flush|ip\s+link\s+.*down|"
    r":\s*\(\s*\)\s*\{|/dev/sd[a-z]\b|"
    # --- Windows / PowerShell 7 (ADR 0011, WIN-1) ---
    # Destructive pwsh cmdlets are distinctive CapCase-hyphenated tokens (low
    # false-positive risk). `Remove-Item` is Tier 3 only WITH a -Recurse/-Force
    # flag, mirroring POSIX `rm` needing `-[rf]` (a bare single-file delete is
    # not Tier 3). The intervening-token count is bounded ({0,16}?) like the
    # `rm` long-option rule, so classify stays linear on `Remove-Item
    # Remove-Item …`. (`rm -Recurse` is already caught by the POSIX `rm\s+-[rf]`
    # rule via case-insensitivity.)
    r"remove-item\b(?:\s+\S+){0,16}?\s+-(?:recurse|force)\b|"
    r"clear-disk|format-volume|initialize-disk|"
    r"stop-computer|restart-computer|"
    r"remove-service|remove-localuser|remove-localgroup|clear-eventlog|"
    # cmd.exe delete/format verbs still reachable from pwsh; require the
    # recursive/quiet slash-flag (or a drive letter for format) so a bare
    # `del file.txt` / `Format-Table` does not over-classify.
    r"(?:del|erase|rd|rmdir)\b(?:\s+\S+){0,8}?\s+/[sq]\b|"
    r"format(?:\s+/\S+){0,4}\s+[a-z]:|diskpart|vssadmin\s+delete\s+shadows|"
    r"bcdedit|cipher\s+/w|(?:reg|sc)(?:\.exe)?\s+delete|wevtutil\s+cl"
    r")"
)

# Substrings that imply a stateful, visible change.
TIER2_PATTERN = re.compile(
    r"(?ix)(?<![\w])("
    r"systemctl\s+(stop|restart|disable|mask|kill)|service\s+\S+\s+(stop|restart)|"
    r"apt(-get)?\s+(install|remove|purge|upgrade|dist-upgrade)|"
    r"yum\s+(install|remove)|dnf\s+(install|remove)|pip\s+install|npm\s+(install|i)\b|"
    r"docker\s+(run|rm|stop|kill|compose|build)|kubectl\s+(apply|delete|scale|rollout)|"
    r"chown|chmod\s+-R|chmod\s+[0-7]{3,4}\s+/|"
    r"crontab|ln\s+-s|mv\s+/|cp\s+-[a-z]*\s+/|sed\s+-i|tee\s+/etc/|"
    r"git\s+(push|commit|merge|rebase)|"
    r"ufw\s+(allow|deny|enable|disable)|"
    r"ssh-copy-id|>\s*/etc/|>>\s*/etc/|"
    # --- Windows / PowerShell 7 (ADR 0011, WIN-1) ---
    # Service control (pwsh cmdlets + sc/net verbs), package install, firewall
    # changes, registry writes, user/task creation, and execution-policy
    # changes — the Windows analogues of systemctl / apt / ufw / crontab above.
    # `sc delete` / `reg delete` are Tier 3 (checked first), so only the
    # non-destructive verbs land here.
    r"stop-service|start-service|restart-service|set-service|"
    r"(?:sc|net)(?:\.exe)?\s+(?:stop|start)\b|"
    r"install-module|install-package|uninstall-module|uninstall-package|"
    r"choco\s+(?:install|uninstall)|winget\s+(?:install|uninstall)|"
    r"(?:remove|disable|set|new)-netfirewallrule|netsh\s+advfirewall|"
    r"(?:reg|sc)(?:\.exe)?\s+(?:add|config)|new-localuser|"
    r"register-scheduledtask|unregister-scheduledtask|schtasks\s+/create|"
    r"set-executionpolicy"
    r")"
)

# Privilege escalation wrappers should not be treated as low-risk commands.
# `runas` covers both `runas /user:Administrator …` and PowerShell's
# `Start-Process … -Verb RunAs` (the `RunAs` verb token matches `\brunas\b`
# case-insensitively) — the Windows analogue of sudo/doas/pkexec (ADR 0011).
PRIV_ESC_PATTERN = re.compile(r"(?ix)\b(sudo|doas|pkexec|runas)\b")
