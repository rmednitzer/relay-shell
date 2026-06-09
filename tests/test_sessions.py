from __future__ import annotations

import asyncio
import os
import re
import signal
from pathlib import Path

import pytest

from relay_shell.config import Settings
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


async def test_pty_spawn_failure_does_not_leak_master_fd() -> None:
    """A failed PTY spawn must release both pty ends, not just the slave.

    Pre-fix, ``LocalPtyTransport.spawn`` closed only ``slave_fd`` in its
    ``finally`` when ``create_subprocess_exec`` raised; the master fd
    leaked once per failed spawn (e.g. a typo'd binary).
    """
    argv = ["/nonexistent-relay-shell-binary"]
    # Warm-up: the first spawn may lazily allocate event-loop plumbing
    # (child-watcher pipes); measure only once that exists.
    with pytest.raises(FileNotFoundError):
        await LocalPtyTransport.spawn(argv, cwd=None, env={}, cols=80, rows=24)
    before = sorted(os.listdir("/proc/self/fd"))
    for _ in range(3):
        with pytest.raises(FileNotFoundError):
            await LocalPtyTransport.spawn(argv, cwd=None, env={}, cols=80, rows=24)
    after = sorted(os.listdir("/proc/self/fd"))
    assert after == before, "failed PTY spawn leaked a file descriptor"


class _RecordingTransport:
    """Transport double that records ``aclose``; satisfies the Protocol."""

    def __init__(self) -> None:
        self.closed = False

    async def write(self, data: bytes) -> None:  # pragma: no cover - unused
        pass

    def resize(self, cols: int, rows: int) -> None:  # pragma: no cover - unused
        pass

    def signal(self, sig: int) -> None:  # pragma: no cover - unused
        pass

    @property
    def returncode(self) -> int | None:
        return None

    async def read_loop(self, sink: object) -> None:
        # Stay "running" until cancelled at teardown, like a live PTY.
        await asyncio.Event().wait()

    async def aclose(self) -> None:
        self.closed = True


async def test_register_session_closes_transport_when_registry_refuses(tmp_path: Path) -> None:
    """The shared spawn-registration path reaps a refused transport (R-003).

    Pre-fix, ``shell_spawn`` / ``ssh_spawn`` registered the freshly-spawned
    transport directly with ``sessions.add``; a refusal (session limit)
    propagated as the tool's error string while the already-running child
    kept running unsupervised.
    """
    from relay_shell.server import Relay

    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        max_sessions=1,
    )
    app = Relay(settings)
    first = _RecordingTransport()
    second = _RecordingTransport()
    try:
        await app.register_session(kind="local", title="one", transport=first, cols=80, rows=24)
        with pytest.raises(SessionError):
            await app.register_session(
                kind="local", title="two", transport=second, cols=80, rows=24
            )
    finally:
        await app.sessions.shutdown()
    assert second.closed, "refused transport must be closed, not leaked"
    assert first.closed  # closed by the registry shutdown, not the failure path
