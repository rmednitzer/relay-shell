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
    # CLI-style flags: --password value, --token=value, --api-key foo
    re.compile(
        r"(?i)(--?(?:password|passwd|pwd|secret|token|api[_-]?key))(?:[=\s]+)\S+",
    ),
    # MySQL-style single-letter -psecret (no space). Anchored to a word
    # boundary so we don't redact "tcp", "lsp", etc.
    re.compile(r"(?<![A-Za-z0-9])-p[^\s=-]\S*"),
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


def redact(text: str) -> str:
    """Replace secret-looking spans in ``text`` with a placeholder."""
    out = _URL_CREDS.sub("://[REDACTED]@", text)
    for pat in _PATTERNS:
        out = pat.sub(_PLACEHOLDER, out)
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
