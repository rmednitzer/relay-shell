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
and escape-aware backslash-space - URL-embedded credentials, and a handful
of provider token shapes. Short-form single-letter flags like ``-p<value>``
are redacted **only** when a MySQL-family CLI (``mysql``, ``mariadb-*``,
``mycli``) appears in the same argument string: ``-p`` is overloaded
across SSH (``-p22``), nmap (``-p1-1000``), and other tools, so the
MySQL-family gate avoids over-redacting unrelated arguments while still
covering the common ``mysql -psecret`` shape. Operators putting DB
passwords on the command line should still prefer ``--password=...``,
the interactive ``-p`` (no value), or ``~/.my.cnf`` instead.

The compiled regex tables live in :mod:`relay_shell.patterns` so a security
reviewer can audit "added a pattern" as a one-file diff.
"""

from __future__ import annotations

from typing import Any

from . import patterns

__all__ = ["redact", "redact_args"]


def redact(text: str) -> str:
    """Replace secret-looking spans in ``text`` with a placeholder."""
    out = patterns.URL_CREDS_PATTERN.sub("://[REDACTED]@", text)
    for pat, repl in patterns.REDACTION_PREFIX_PATTERNS:
        out = pat.sub(repl, out)
    for pat in patterns.REDACTION_PATTERNS:
        out = pat.sub(patterns.REDACTION_PLACEHOLDER, out)
    if patterns.MYSQL_FAMILY_CLI_PATTERN.search(out):
        out = patterns.MYSQL_COMPACT_PASSWORD_PATTERN.sub(
            lambda m: f"{m.group(1)}{patterns.REDACTION_PLACEHOLDER}", out
        )
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
