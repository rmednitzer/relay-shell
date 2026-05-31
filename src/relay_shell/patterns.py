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
PATTERNS_VERSION = "4"

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
    # token=... / api[_-]?key=... / password: ...
    (
        re.compile(
            r"(?i)\b(?P<prefix>(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*)\S+"
        ),
        r"\g<prefix>[REDACTED]",
    ),
    # CLI-style flags: ``--password value``, ``--token=value``,
    # ``--api-key "two words"``, ``--password top\ secret``. See the
    # docstring of :mod:`relay_shell.redaction` for scope and the reasoning
    # around interactive flags / dash-prefixed values.
    (
        re.compile(
            r"""(?ix)
            (?P<prefix>
                --?(?:password|passwd|pwd|secret|token|api[_-]?key)
                [=\ \t]+
            )
            (?:
                "(?:[^"\\]|\\.)*"        # double-quoted, escape-aware
              | '(?:[^'\\]|\\.)*'        # single-quoted, escape-aware
              | (?:-(?!-)|(?!--))(?:\\.|\S)+
                                        # bare value, treating \\<char> as one unit;
                                        # allow single-dash-prefixed secrets (-abc)
                                        # but still reject next long option (--host)
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
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
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
    # AWS access key id (fixed-length AKIA + 16).
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Slack token family (bot/user/app/refresh/legacy).
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
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
    r"(?ix)\b("
    r"rm\s+-[rf]|rm\s+-[a-z]*f|shred|mkfs|fdisk|sgdisk|wipefs|"
    r"dd\s+[^|]*of=/dev/|>\s*/dev/[sh]d|"
    r"shutdown|reboot|halt|poweroff|init\s+0|init\s+6|"
    r"drop\s+database|drop\s+table|truncate\s+table|"
    r"git\s+push\s+.*--force|git\s+reset\s+--hard|"
    r"userdel|deluser|gpasswd|passwd\s+|"
    r"iptables\s+-F|nft\s+flush|ip\s+link\s+.*down|"
    r":\s*\(\s*\)\s*\{|/dev/sd[a-z]\b"
    r")"
)

# Substrings that imply a stateful, visible change.
TIER2_PATTERN = re.compile(
    r"(?ix)\b("
    r"systemctl\s+(stop|restart|disable|mask|kill)|service\s+\S+\s+(stop|restart)|"
    r"apt(-get)?\s+(install|remove|purge|upgrade|dist-upgrade)|"
    r"yum\s+(install|remove)|dnf\s+(install|remove)|pip\s+install|npm\s+(install|i)\b|"
    r"docker\s+(run|rm|stop|kill|compose|build)|kubectl\s+(apply|delete|scale|rollout)|"
    r"chown|chmod\s+-R|chmod\s+[0-7]{3,4}\s+/|"
    r"crontab|ln\s+-s|mv\s+/|cp\s+-[a-z]*\s+/|sed\s+-i|tee\s+/etc/|"
    r"git\s+(push|commit|merge|rebase)|"
    r"ufw\s+(allow|deny|enable|disable)|"
    r"ssh-copy-id|>\s*/etc/|>>\s*/etc/"
    r")"
)

# Privilege escalation wrappers should not be treated as low-risk commands.
PRIV_ESC_PATTERN = re.compile(r"(?ix)\b(sudo|doas|pkexec)\b")
