from __future__ import annotations

import os
import signal

import pytest

from mcpx.errors import SessionError
from mcpx.sessions import LocalPtyTransport, SessionRegistry


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
