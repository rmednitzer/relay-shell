from __future__ import annotations

from relay_shell.errors import PolicyDenied, RelayError, SessionError, fmt_exc


def test_fmt_exc_uses_class_and_message() -> None:
    line = fmt_exc(ValueError("bad input"))
    assert line.startswith("[ERROR: ValueError:")
    assert "bad input" in line
    assert "\n" not in line  # single bounded line


def test_fmt_exc_falls_back_to_class_when_message_empty() -> None:
    # Some exceptions stringify to "" (no args); we should not emit a bare colon.
    line = fmt_exc(RuntimeError())
    assert "RuntimeError" in line
    assert "[ERROR:" in line


def test_relay_error_hierarchy() -> None:
    assert issubclass(PolicyDenied, RelayError)
    assert issubclass(SessionError, RelayError)
    assert issubclass(RelayError, Exception)
