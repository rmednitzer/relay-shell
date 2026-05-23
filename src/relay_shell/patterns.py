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
# removed). Initial extraction from redaction.py + policy.py is version 1.
PATTERNS_VERSION = "1"

REDACTION_PLACEHOLDER = "[REDACTED]"


# --- Redaction: structure-preserving (keep the prefix, replace the value) ---

REDACTION_PREFIX_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization / Proxy-Authorization header value
    (
        re.compile(r"(?i)\b(?P<prefix>(?:proxy-)?authorization\s*[:=]\s*)\S+"),
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

REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PEM / OpenSSH private key blocks
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # Common provider token shapes
    re.compile(r"\bgith(?:ub)?_pat_[A-Za-z0-9_]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
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
