"""Secret redaction for the audit trail.

Audited arguments are scrubbed before they are written so that the audit log
(which is meant to be shipped off-host) never becomes a secret store. The
output *body* is never logged at all (only its hash); this module covers the
*argument* surface, where a caller might pass a token or key inline.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["redact", "redact_args"]

_PLACEHOLDER = "[REDACTED]"

# Ordered, conservative patterns. Each replaces the secret-bearing span only.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PEM / OpenSSH private key blocks
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # Authorization / Proxy-Authorization header value
    re.compile(r"(?i)\b(proxy-)?authorization\s*[:=]\s*\S+"),
    # Bearer / token=... / api[_-]?key=...
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*\S+"),
    # CLI-style flags: ``--password value``, ``--token=value``,
    # ``--api-key "two words"``. The value is either a single bare token
    # (with negative lookahead on ``-`` so we don't eat the next option),
    # or a fully quoted string - escape-aware - so passphrase secrets with
    # embedded whitespace are scrubbed as a unit instead of leaking the
    # trailing words.
    re.compile(
        r"""(?ix)
        --?(?:password|passwd|pwd|secret|token|api[_-]?key)
        [=\s]+
        (?:
            "(?:[^"\\]|\\.)*"     # double-quoted, escape-aware
          | '(?:[^'\\]|\\.)*'     # single-quoted, escape-aware
          | (?!-)\S+              # bare value not starting with a dash
        )
        """,
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

# Short-form ``-p<value>`` is dangerously overloaded: mysql password vs
# ssh/nmap port spec vs generic ``-proxy`` and long options like
# ``--protocol``. Two narrowings stack:
#   * the lookbehind excludes a leading ``-`` so we never start matching at
#     the second dash of a long option (``--protocol`` -> no match);
#   * application is per-line and gated on the same line containing a
#     mysql-family token, so a multi-line script with both ``mysql -psecret``
#     and a later ``ssh -p22`` only redacts the mysql line.
_DB_CLI = re.compile(r"\b(?:mysql|mariadb|mysqldump|mysqladmin|mycli)\b")
_DB_PASSWORD_FLAG = re.compile(r"(?<![A-Za-z0-9-])(-p)[^\s=-]\S*")


def _scrub_db_password_in_line(line: str) -> str:
    if not _DB_CLI.search(line):
        return line
    return _DB_PASSWORD_FLAG.sub(lambda m: f"{m.group(1)}{_PLACEHOLDER}", line)


def redact(text: str) -> str:
    """Replace secret-looking spans in ``text`` with a placeholder."""
    out = _URL_CREDS.sub("://[REDACTED]@", text)
    for pat in _PATTERNS:
        out = pat.sub(_PLACEHOLDER, out)
    if _DB_CLI.search(out):
        # Per-line scoping: only lines that themselves carry a mysql-family
        # token are eligible for the overloaded ``-p<value>`` substitution.
        out = "\n".join(_scrub_db_password_in_line(line) for line in out.split("\n"))
    return out


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
