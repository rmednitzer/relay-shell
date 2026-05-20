"""Secret redaction for the audit trail.

Audited arguments are scrubbed before they are written so that the audit log
(which is meant to be shipped off-host) never becomes a secret store. The
output *body* is never logged at all (only its hash); this module covers the
*argument* surface, where a caller might pass a token or key inline.

Scope is deliberately bounded. The patterns target well-defined syntaxes:
PEM blocks, ``Authorization`` headers, ``Bearer``/``key=value`` pairs,
long-name CLI flags - matching either a double dash (``--password=...``,
``--token VALUE``) or the single-dash long-name style some Go-flavored
tools use (``-token=foo``, ``-password VALUE``), including quoted values
and escape-aware backslash-space - URL-embedded credentials, a handful
of provider token shapes, and MySQL-family short-form ``-p<value>`` when used
with known DB CLI commands (for example, ``mysql -psecret``). To avoid
over-redacting unrelated ``-p`` usage (SSH ports, nmap ranges, ``-proxy``),
short ``-p`` scrubbing is limited to lines that include a known MySQL-family
command token.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["redact", "redact_args"]

_PLACEHOLDER = "[REDACTED]"

# Ordered, conservative patterns. Prefer structure-preserving replacements (keep
# the non-secret prefix) when feasible; otherwise collapse the matched region to
# the placeholder.
_PREFIX_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
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
    # ``--api-key "two words"``, ``--password top\ secret``. See the module
    # docstring for scope and the reasoning around interactive flags.
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
              | (?!-)(?:\\.|\S)+         # bare value, treating \\<char> as one unit
            )
            """,
        ),
        r"\g<prefix>[REDACTED]",
    ),
)

_PATTERNS: tuple[re.Pattern[str], ...] = (
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

# URL-embedded credentials (``user:pass@host``) need a structure-preserving
# replacement; everything else collapses to the placeholder.
_URL_CREDS = re.compile(r"://[^/\s:@]+:[^/\s:@]+@")



_DB_CLI = re.compile(r"(?i)\b(?:mysql|mariadb|mysqldump|mysqladmin)\b")
_DB_PASSWORD_FLAG = re.compile(r"(?<!\S)-p(?P<secret>[^\s'\"]+)")


def _redact_db_dash_p(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines(keepends=True):
        if _DB_CLI.search(line):
            line = _DB_PASSWORD_FLAG.sub("-p[REDACTED]", line)
        lines.append(line)
    return "".join(lines)


def redact(text: str) -> str:
    """Replace secret-looking spans in ``text`` with a placeholder."""
    out = _URL_CREDS.sub("://[REDACTED]@", text)
    for pat, repl in _PREFIX_PATTERNS:
        out = pat.sub(repl, out)
    for pat in _PATTERNS:
        out = pat.sub(_PLACEHOLDER, out)
    return _redact_db_dash_p(out)


def _scrub(value: Any, max_len: int) -> Any:
    if isinstance(value, str):
        red = redact(value)
        if len(red) > max_len:
            red = red[:max_len] + f"...(+{len(red) - max_len})"
        return red
    if isinstance(value, dict):
        return {k: _scrub(v, max_len) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v, max_len) for v in value]
    return value


def redact_args(args: dict[str, Any], max_len: int = 500) -> dict[str, Any]:
    """Return a redacted, length-bounded copy of an audit-argument mapping."""
    return {k: _scrub(v, max_len) for k, v in args.items()}
