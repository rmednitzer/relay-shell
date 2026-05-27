from __future__ import annotations

import os
import re
import signal

import pytest

from relay_shell.errors import SessionError
from relay_shell.sessions import LocalPtyTransport, SessionRegistry


async def _spawn(reg: SessionRegistry, argv: list[str]) -> str:
    tr = await LocalPtyTransport.spawn(argv, cwd=None, env=dict(os.environ), cols=80, rows=24)
    sess = await reg.add(kind="local", title=" ".join(argv), transport=tr, cols=80, rows=24)
    return sess.id


async def test_local_pty_roundtrip() -> None:
    reg = SessionRegistry(max_sessions=8, idle_timeout=60, buffer_cap=65536)
    try:
        sid = await _spawn(reg, ["/bin/cat"])
        await reg.send(sid, b"ping-123\n")
        out = await reg.recv(sid, timeout=3.0, max_bytes=4096)
        assert "ping-123" in out
        await reg.kill(sid, signal.SIGTERM)
        await reg.close(sid)
    finally:
        await reg.shutdown()


async def test_recv_timeout_returns_empty_quickly() -> None:
    reg = SessionRegistry(8, 60, 65536)
    try:
        sid = await _spawn(reg, ["/bin/cat"])
        out = await reg.recv(sid, timeout=0.2, max_bytes=1024)
        assert out == ""
    finally:
        await reg.shutdown()


async def test_session_limit_enforced() -> None:
    reg = SessionRegistry(max_sessions=1, idle_timeout=60, buffer_cap=4096)
    try:
        await _spawn(reg, ["/bin/cat"])
        with pytest.raises(SessionError):
            await _spawn(reg, ["/bin/cat"])
    finally:
        await reg.shutdown()


async def test_unknown_session_raises() -> None:
    reg = SessionRegistry(8, 60, 4096)
    with pytest.raises(SessionError):
        await reg.recv("nope", 0.1, 100)


async def test_closed_session_reports_exit() -> None:
    reg = SessionRegistry(8, 60, 65536)
    try:
        sid = await _spawn(reg, ["/bin/sh", "-c", "echo done; exit 0"])
        seen = ""
        for _ in range(20):
            seen += await reg.recv(sid, timeout=0.5, max_bytes=4096)
            if "ended" in seen or "done" in seen:
                break
        assert "done" in seen or "ended" in seen
    finally:
        await reg.shutdown()


async def test_session_recv_ended_message_shape_with_exit() -> None:
    """Pin the exact wire shape of the ``ended`` sentinel when exit_code is known.

    Client renderers grep for this marker; if the format ever drifts they
    stop highlighting closed sessions and operators lose the visual cue.
    Freeze the shape (leading newline, bracket pair, ``exit=N`` field).
    Both branches (with/without exit) live next to each other in
    ``SessionRegistry.recv`` so a single refactor could silently break
    either; test both.
    """
    reg = SessionRegistry(8, 60, 65536)
    pattern = re.compile(r"^\n\[session [A-Za-z0-9_\-]+ ended, exit=-?\d+\]$")
    try:
        sid = await _spawn(reg, ["/bin/sh", "-c", "exit 0"])
        sess = reg._sessions[sid]
        # Drain any preamble so we hit the closed-buffer branch.
        for _ in range(40):
            await reg.recv(sid, timeout=0.2, max_bytes=4096)
            if sess.closed and not sess.buffer:
                break
        # Pin both branches at the public API by forcing exit_code
        # directly. This bypasses the timing dance of waiting for the
        # OS to set returncode on the asyncio.subprocess.Process; the
        # branch we are testing is "closed and exit_code is not None"
        # vs "closed and exit_code is None" — the source of exit_code
        # is irrelevant to the wire-format contract.
        sess.exit_code = 7
        out = await reg.recv(sid, timeout=0.1, max_bytes=4096)
        assert pattern.match(out), f"unexpected ended shape: {out!r}"
        assert out == f"\n[session {sid} ended, exit=7]"
    finally:
        await reg.shutdown()


async def test_session_recv_ended_message_shape_without_exit() -> None:
    """When ``exit_code`` is None at teardown, the marker omits the exit field."""
    reg = SessionRegistry(8, 60, 65536)
    pattern = re.compile(r"^\n\[session [A-Za-z0-9_\-]+ ended\]$")
    try:
        sid = await _spawn(reg, ["/bin/sh", "-c", "exit 0"])
        sess = reg._sessions[sid]
        for _ in range(40):
            await reg.recv(sid, timeout=0.2, max_bytes=4096)
            if sess.closed and not sess.buffer:
                break
        sess.exit_code = None
        out = await reg.recv(sid, timeout=0.1, max_bytes=4096)
        assert pattern.match(out), f"unexpected ended shape: {out!r}"
        assert out == f"\n[session {sid} ended]"
    finally:
        await reg.shutdown()
