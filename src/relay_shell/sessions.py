"""Unified session registry for local PTYs and SSH PTYs.

A *session* is a long-lived interactive process behind a pseudo-terminal. The
registry is transport-agnostic: any object implementing :class:`Transport`
(a local PTY, an SSH remote process) is driven the same way, so the
``session_*`` tools work uniformly across local and remote sessions.

Design choices for reliability:

* Bounded everything - max session count, per-session ring buffer, idle and
  lifetime reaping. Memory cannot grow without bound.
* Opportunistic sweeping on every create/list call, so a dead or idle session
  is reclaimed without a fragile always-on background task.
* ``recv`` clears its wakeup event *under the buffer lock* immediately before
  awaiting, and the reader sets it *under the same lock* after appending, so
  there is no lost-wakeup race.
* A reader task per session ends naturally on EOF; failures are contained and
  mark the session closed rather than propagating.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import pty
import signal
import struct
import termios
import time
from dataclasses import dataclass, field
from typing import Protocol

from .errors import SessionError
from .util import gen_id

__all__ = ["LocalPtyTransport", "Session", "SessionRegistry", "Transport"]

_READ_CHUNK = 65536


class Transport(Protocol):
    """The minimal contract a session backend must satisfy."""

    async def write(self, data: bytes) -> None: ...

    def resize(self, cols: int, rows: int) -> None: ...

    def signal(self, sig: int) -> None: ...

    @property
    def returncode(self) -> int | None: ...

    async def read_loop(self, sink: object) -> None: ...

    async def aclose(self) -> None: ...


def _set_winsize(fd: int, cols: int, rows: int) -> None:
    with contextlib.suppress(OSError):
        packed = struct.pack("HHHH", max(1, rows), max(1, cols), 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)


class LocalPtyTransport:
    """A local child process attached to a pseudo-terminal."""

    def __init__(self, master_fd: int, proc: asyncio.subprocess.Process) -> None:
        self._fd = master_fd
        self._proc = proc
        self._closed = False

    @classmethod
    async def spawn(
        cls,
        argv: list[str],
        *,
        cwd: str | None,
        env: dict[str, str],
        cols: int,
        rows: int,
    ) -> LocalPtyTransport:
        master_fd, slave_fd = pty.openpty()
        _set_winsize(slave_fd, cols, rows)
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=cwd or None,
                env=env,
                start_new_session=True,
            )
        finally:
            os.close(slave_fd)
        return cls(master_fd, proc)

    async def write(self, data: bytes) -> None:
        loop = asyncio.get_running_loop()
        view = memoryview(data)
        while view:
            try:
                written = os.write(self._fd, view)
                view = view[written:]
            except BlockingIOError:
                fut: asyncio.Future[None] = loop.create_future()

                def _ready(f: asyncio.Future[None] = fut) -> None:
                    if not f.done():
                        f.set_result(None)

                loop.add_writer(self._fd, _ready)
                try:
                    await fut
                finally:
                    loop.remove_writer(self._fd)
            except OSError:
                return

    def resize(self, cols: int, rows: int) -> None:
        _set_winsize(self._fd, cols, rows)

    def signal(self, sig: int) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(os.getpgid(self._proc.pid), sig)

    @property
    def returncode(self) -> int | None:
        return self._proc.returncode

    async def read_loop(self, sink: object) -> None:
        assert callable(sink)
        loop = asyncio.get_running_loop()
        event = asyncio.Event()
        try:
            loop.add_reader(self._fd, event.set)
        except NotImplementedError:
            await self._thread_read_loop(sink)
            return
        try:
            while True:
                await event.wait()
                event.clear()
                while True:
                    try:
                        chunk = os.read(self._fd, _READ_CHUNK)
                    except BlockingIOError:
                        break
                    except OSError:
                        chunk = b""
                    if not chunk:
                        return
                    sink(chunk)
        finally:
            with contextlib.suppress(OSError, ValueError):
                loop.remove_reader(self._fd)

    async def _thread_read_loop(self, sink: object) -> None:
        assert callable(sink)
        loop = asyncio.get_running_loop()
        flags = fcntl.fcntl(self._fd, fcntl.F_GETFL)
        fcntl.fcntl(self._fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

        def _read() -> bytes:
            try:
                return os.read(self._fd, _READ_CHUNK)
            except OSError:
                return b""

        while True:
            chunk = await loop.run_in_executor(None, _read)
            if not chunk:
                return
            sink(chunk)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(self._proc.wait(), 5)
        except (TimeoutError, ProcessLookupError):
            self.signal(signal.SIGKILL)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), 2)
        finally:
            with contextlib.suppress(OSError):
                os.close(self._fd)


@dataclass
class Session:
    id: str
    kind: str
    title: str
    transport: Transport
    cols: int
    rows: int
    created: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)
    buffer: bytearray = field(default_factory=bytearray)
    produced: int = 0
    dropped: int = 0
    closed: bool = False
    exit_code: int | None = None
    _event: asyncio.Event = field(default_factory=asyncio.Event)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _reader: asyncio.Task[None] | None = None


class SessionRegistry:
    """Owns all live sessions and enforces the resource envelope."""

    def __init__(self, max_sessions: int, idle_timeout: float, buffer_cap: int) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()
        self._max = max_sessions
        self._idle = idle_timeout
        self._cap = buffer_cap

    async def add(
        self,
        *,
        kind: str,
        title: str,
        transport: Transport,
        cols: int,
        rows: int,
    ) -> Session:
        await self._sweep()
        async with self._lock:
            if len(self._sessions) >= self._max:
                raise SessionError(
                    f"session limit reached ({self._max}); close idle sessions first"
                )
            sid = gen_id("ssh" if kind == "ssh" else "sh")
            sess = Session(
                id=sid, kind=kind, title=title, transport=transport, cols=cols, rows=rows
            )
            self._sessions[sid] = sess

        def _sink(data: bytes) -> None:
            sess.produced += len(data)
            sess.buffer += data
            overflow = len(sess.buffer) - self._cap
            if overflow > 0:
                del sess.buffer[:overflow]
                sess.dropped += overflow
            if not sess._event.is_set():
                sess._event.set()

        sess._reader = asyncio.create_task(self._run_reader(sess, _sink))
        return sess

    async def _run_reader(self, sess: Session, sink: object) -> None:
        try:
            await sess.transport.read_loop(sink)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - contain backend failures
            pass
        finally:
            sess.closed = True
            sess.exit_code = sess.transport.returncode
            sess._event.set()

    async def _get(self, sid: str) -> Session:
        async with self._lock:
            sess = self._sessions.get(sid)
        if sess is None:
            raise SessionError(f"unknown session: {sid}")
        return sess

    async def send(self, sid: str, data: bytes) -> None:
        sess = await self._get(sid)
        sess.last_used = time.monotonic()
        await sess.transport.write(data)

    async def recv(self, sid: str, timeout: float, max_bytes: int) -> str:
        sess = await self._get(sid)
        sess.last_used = time.monotonic()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, timeout)
        while True:
            async with sess._lock:
                if sess.buffer:
                    take = bytes(sess.buffer[:max_bytes])
                    del sess.buffer[: len(take)]
                    text = take.decode("utf-8", "replace")
                    if not sess.buffer and not sess.closed:
                        sess._event.clear()
                    return text
                if sess.closed:
                    if sess.exit_code is not None:
                        return f"\n[session {sid} ended, exit={sess.exit_code}]"
                    return f"\n[session {sid} ended]"
                sess._event.clear()
            remaining = deadline - loop.time()
            if remaining <= 0:
                return ""
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sess._event.wait(), remaining)

    async def resize(self, sid: str, cols: int, rows: int) -> None:
        sess = await self._get(sid)
        sess.cols, sess.rows = cols, rows
        sess.last_used = time.monotonic()
        sess.transport.resize(cols, rows)

    async def kill(self, sid: str, sig: int) -> None:
        sess = await self._get(sid)
        sess.transport.signal(sig)
        sess.last_used = time.monotonic()

    async def close(self, sid: str) -> None:
        async with self._lock:
            sess = self._sessions.pop(sid, None)
        if sess is None:
            raise SessionError(f"unknown session: {sid}")
        await self._teardown(sess)

    async def _teardown(self, sess: Session) -> None:
        if sess._reader is not None:
            sess._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await sess._reader
        with contextlib.suppress(Exception):
            await sess.transport.aclose()
        sess.closed = True

    def snapshot(self, sid: str, sess: Session) -> dict[str, object]:
        now = time.monotonic()
        return {
            "id": sid,
            "kind": sess.kind,
            "title": sess.title,
            "size": f"{sess.cols}x{sess.rows}",
            "age_s": round(now - sess.created, 1),
            "idle_s": round(now - sess.last_used, 1),
            "buffered": len(sess.buffer),
            "produced": sess.produced,
            "dropped": sess.dropped,
            "closed": sess.closed,
            "exit_code": sess.exit_code,
        }

    async def list(self) -> list[dict[str, object]]:
        await self._sweep()
        async with self._lock:
            return [self.snapshot(sid, s) for sid, s in self._sessions.items()]

    def count(self) -> int:
        """Synchronous count of currently-tracked sessions, for /metrics."""
        return len(self._sessions)

    async def _sweep(self) -> None:
        now = time.monotonic()
        doomed: list[Session] = []
        async with self._lock:
            for sid in list(self._sessions):
                sess = self._sessions[sid]
                idle = now - sess.last_used
                if (sess.closed and not sess.buffer and idle > 5) or idle > self._idle:
                    doomed.append(self._sessions.pop(sid))
        for sess in doomed:
            await self._teardown(sess)

    async def shutdown(self) -> None:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for sess in sessions:
            await self._teardown(sess)
