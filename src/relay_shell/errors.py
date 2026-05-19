"""Error types and a uniform error-string formatter.

Tools never raise into the MCP transport; every failure becomes a bounded,
auditable string. These helpers make that consistent.
"""

from __future__ import annotations

__all__ = ["PolicyDenied", "RelayError", "SessionError", "fmt_exc"]


class RelayError(Exception):
    """Base class for expected, operator-facing errors."""


class PolicyDenied(RelayError):
    """Raised/returned when the policy layer refuses a call."""


class SessionError(RelayError):
    """Raised when a session id is unknown or a session operation fails."""


def fmt_exc(exc: BaseException) -> str:
    """Render an exception as a single bounded line for tool output."""
    msg = str(exc).strip() or exc.__class__.__name__
    return f"[ERROR: {exc.__class__.__name__}: {msg}]"
