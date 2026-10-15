"""Unified session registry for local PTYs and SSH PTYs.

A *session* is a long-lived interactive process behind a pseudo-terminal. The
registry is transport-agnostic: any object implementing :class:`Transport`
(a local PTY, an SSH remote process) is driven the same way, so the
``session_*`` tools work uniformly across local and remote sessions.

Design choices for reliability:

* Bounded everything: max session count, per-session ring buffer, idle and
  lifetime reaping.
* Opportunistic sweeping on every create/list call, so a dead or idle session
  is reclaimed without an always-on background task.
* ``recv`` clears its wakeup event *under the buffer lock* immediately
  before awaiting. The reader callback (``_sink``) is a synchronous
  ``add_reader`` callback on the asyncio event loop, so its buffer/event
  mutations cannot interleave with a ``recv`` task: the single-threaded loop,
  not the lock, serializes them, and the lost-wakeup invariant holds without
  ``_sink`` taking the lock. If the reader ever moves off the event loop (e.g.
  a dedicated thread), ``_sink`` must acquire ``sess._lock`` to keep it.
* A reader task per session ends on EOF; failures are contained and mark the
  session closed rather than propagating.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import pty
import re
import signal
import struct
import termios
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from . import patterns, seccomp
from .errors import SessionError
from .util import gen_id

__all__ = ["LocalPtyTransport", "Session", "SessionRegistry", "Transport"]

_READ_CHUNK = 65536
# Characters that end or discard the line being typed into a PTY: Enter (LF/CR),
# Ctrl-C and Ctrl-U. Everything typed since the last of these is one pending line.
_LINE_RESET = "\n\r\x03\x15"
_PENDING_MAX = 4096


def _advance_line(pending: str, typed: str) -> str:
    """The partial line left on a PTY after ``typed`` is written after ``pending``."""
    cut = max(typed.rfind(ch) for ch in _LINE_RESET)
    line = typed[cut + 1 :] if cut >= 0 else pending + typed
    return line[-_PENDING_MAX:]


_TAIL_BYTES = 512
# CSI and OSC escape sequences, stripped before looking at the prompt text.
_ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def _looks_like_secret_prompt(tail: bytes) -> bool:
    text = _ANSI_RE.sub(b"", tail).decode("utf-8", "replace").rstrip(" \t")
    last = re.split(r"[\r\n]", text)[-1]
    return bool(patterns.SECRET_PROMPT_PATTERN.search(last))


def _utf8_cut(data: bytes | bytearray, limit: int) -> int:
    """Largest ``n <= limit`` that does not split a UTF-8 character at ``data[n]``.

    ``recv`` consumes what it returns, so cutting a multibyte character in half would
    turn both halves into permanent replacement characters. Falls back to ``limit`` if
    no boundary is found within one character's width (binary data).
    """
    if len(data) <= limit:
        return len(data)
    end = limit
    while end > 0 and limit - end < 4 and (data[end] & 0xC0) == 0x80:
        end -= 1
    return end if end > 0 and (data[end] & 0xC0) != 0x80 else limit


class Transport(Protocol):
    """The minimal contract a session backend must satisfy."""

    async def write(self, data: bytes) -> None: ...

    def resize(self, cols: int, rows: int) -> None: ...

    def signal(self, sig: int) -> None: ...

    @property
    def returncode(self) -> int | None: ...

    async def read_loop(self, sink: object) -> None: ...

    async def aclose(self) -> None: ...


# Teardown signal schedule for a local PTY child: SIGTERM at 0, SIGHUP once
# `_HANGUP_AFTER` has passed, SIGKILL at `_TERM_GRACE` (all seconds).
_TERM_GRACE = 5.0
_HANGUP_AFTER = 0.5


def _set_winsize(fd: int, cols: int, rows: int) -> None:
    with contextlib.suppress(OSError):
        # Clamp to unsigned short: above 65535 struct.pack raises struct.error
        # (not OSError), which would leak the pty fds in spawn().
        packed = struct.pack("HHHH", min(max(1, rows), 0xFFFF), min(max(1, cols), 0xFFFF), 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)


class LocalPtyTransport:
    """A local child process attached to a pseudo-terminal."""

    def __init__(
        self,
        master_fd: int,
        proc: asyncio.subprocess.Process,
        monitor: seccomp.SeccompMonitor | None = None,
    ) -> None:
        self._fd = master_fd
        self._proc = proc
        self._monitor = monitor
        self._closed = False
        # start_new_session makes the child a group leader (pgid == pid). Kept
        # because os.getpgid(pid) fails once the leader is reaped while
        # descendants in the group may still run.
        self._pgid = proc.pid

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
        # Opt-in seccomp-notify audit channel (ADR 0006, B-026). `extras` is {}
        # unless the active per-call monitor armed (CAP_SYS_ADMIN + enabled).
        # Unlike the one-shot executor (shelltools), the monitor must outlive
        # the tool call: the child holds the filter for its whole life, so the
        # transport adopts the monitor and stop() happens in aclose().
        monitor = seccomp.get_active()
        extras = monitor.arm() if monitor is not None else {}
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=cwd or None,
                env=env,
                start_new_session=True,
                **extras,  # type: ignore[arg-type]
            )
        except BaseException:
            # No child: release the supervisor and the master end (the slave
            # end closes in the finally below either way).
            if monitor is not None:
                monitor.stop()
            with contextlib.suppress(OSError):
                os.close(master_fd)
            raise
        finally:
            os.close(slave_fd)
        return cls(master_fd, proc, monitor)

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

    def echo_off(self) -> bool:
        """True while the terminal has ECHO cleared (a password is being read)."""
        try:
            return not termios.tcgetattr(self._fd)[3] & termios.ECHO
        except (termios.error, OSError, ValueError):
            return False

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
        # POSIX-only module, so the selector loop's add_reader is always available.
        loop.add_reader(self._fd, event.set)
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

    def _group_alive(self) -> bool:
        try:
            os.killpg(self._pgid, 0)
        except OSError:
            return False
        return True

    def _kill_group(self) -> None:
        with contextlib.suppress(OSError):
            os.killpg(self._pgid, signal.SIGKILL)

    async def _reap_group(self, deadline: float) -> None:
        """Once the leader is gone, give the rest of its group until ``deadline``, then SIGKILL.

        The leader exiting on SIGTERM or SIGHUP says nothing about descendants in its
        group that ignore both; without this a close returned while they ran on with their
        session removed. Descendants that handle SIGTERM get the remaining grace before
        SIGKILL; an empty group costs one syscall.
        """
        loop = asyncio.get_running_loop()
        try:
            # Polled: a process group has no awaitable handle (pidfds are per process).
            while self._group_alive() and loop.time() < deadline:  # noqa: ASYNC110
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            self._kill_group()
            raise
        self._kill_group()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        deadline = asyncio.get_running_loop().time() + _TERM_GRACE
        self.signal(signal.SIGTERM)
        try:
            try:
                await asyncio.wait_for(self._proc.wait(), _HANGUP_AFTER)
            except TimeoutError:
                # Interactive shells ignore SIGTERM but exit on SIGHUP (what a
                # closing terminal sends); without it every close sat out the whole
                # grace period and ended in SIGKILL. SIGHUP follows SIGTERM only
                # after a short grace so a daemon that traps SIGTERM for orderly
                # shutdown (and treats SIGHUP as "reload") is not hung up mid-shutdown.
                self.signal(signal.SIGHUP)
                await asyncio.wait_for(self._proc.wait(), _TERM_GRACE - _HANGUP_AFTER)
            await self._reap_group(deadline)
        except asyncio.CancelledError:
            # `_closed` is already set, so no second aclose will follow; a child
            # that ignores SIGTERM would outlive its session, so kill it first.
            self.signal(signal.SIGKILL)
            raise
        except (TimeoutError, ProcessLookupError, RuntimeError):
            # RuntimeError: the process handle is bound to another (closed) event
            # loop, as in the shutdown path, so it cannot be awaited; still kill it.
            self.signal(signal.SIGKILL)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), 2)
        finally:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            if self._monitor is not None:
                # The supervisor has already drained (the notify fd hangs up when
                # the filtered task tree dies); this joins its thread and releases
                # its fds. Idempotent.
                self._monitor.stop()


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
    # Number of `recv()` calls long-polling this session. A live waiter means
    # the session is in use, so the idle sweep must not reap it: a
    # `recv(timeout=T)` longer than the idle timeout would otherwise be torn
    # down mid-wait. Mutated only on the event-loop thread with no `await`
    # between read and write, so it needs no lock.
    _waiters: int = 0
    # The line being typed (text sent since the last Enter / Ctrl-C / Ctrl-U). The
    # policy classifies this plus the next send, so a destructive command split
    # across several `session_send` calls is seen whole.
    pending: str = ""
    # The last few hundred bytes the session produced, kept (independently of the
    # recv buffer, which `recv` drains) so the registry can tell whether the
    # session is sitting at a secret prompt. Cleared when input is sent.
    tail: bytearray = field(default_factory=bytearray)


class SessionRegistry:
    """Owns all live sessions and enforces the resource envelope."""

    def __init__(self, max_sessions: int, idle_timeout: float, buffer_cap: int) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()
        self._teardowns: set[asyncio.Future[Any]] = set()
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
            sess.tail += data
            if len(sess.tail) > _TAIL_BYTES:
                del sess.tail[:-_TAIL_BYTES]
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

    async def pending_input(self, sid: str) -> str:
        """The partial line already typed into the session (never raises)."""
        async with self._lock:
            sess = self._sessions.get(sid)
        return sess.pending if sess is not None else ""

    async def awaiting_secret(self, sid: str) -> bool:
        """True if the session is at a prompt for a secret (never raises).

        Two independent signals: the last output line reads like a password
        prompt (works for local and SSH sessions), or the local PTY has echo
        switched off (what ``sudo``/``ssh``/``passwd`` do while reading one).
        Used so the audit trail can withhold the next input, which has no
        keyword for pattern redaction to find.
        """
        async with self._lock:
            sess = self._sessions.get(sid)
        if sess is None:
            return False
        echo_off = getattr(sess.transport, "echo_off", None)
        if callable(echo_off):
            with contextlib.suppress(Exception):
                if echo_off():
                    return True
        return _looks_like_secret_prompt(bytes(sess.tail))

    async def send(self, sid: str, data: bytes) -> None:
        sess = await self._get(sid)
        sess.last_used = time.monotonic()
        sess.pending = _advance_line(sess.pending, data.decode("utf-8", "replace"))
        sess.tail.clear()  # the prompt (if any) is being answered now
        await sess.transport.write(data)

    async def recv(self, sid: str, timeout: float, max_bytes: int) -> str:
        sess = await self._get(sid)
        # last_used at entry is not enough when the wait outlasts the idle
        # timeout, so `_sweep` also skips sessions with a live waiter. Both
        # writes have no intervening await, so a concurrent sweep sees a
        # consistent (last_used=now, waiter present) state.
        sess.last_used = time.monotonic()
        sess._waiters += 1
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + max(0.0, timeout)
            while True:
                async with sess._lock:
                    if sess.buffer:
                        take = bytes(sess.buffer[: _utf8_cut(sess.buffer, max_bytes)])
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
        finally:
            sess._waiters -= 1
            sess.last_used = time.monotonic()

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
        await self._teardown_unregistered([sess])

    async def _teardown_unregistered(self, sessions: list[Session]) -> None:
        """Tear down sessions that are already out of the registry, to completion.

        Once popped, a session is reachable only from here, so a caller cancelled
        part-way (client disconnect, MCP cancellation) must not abandon it: the
        teardown runs as its own task and the caller merely stops waiting for it.
        The sessions close concurrently, so one slow child does not delay the rest.
        """
        if not sessions:
            return
        task = asyncio.ensure_future(
            asyncio.gather(*(self._teardown(s) for s in sessions), return_exceptions=True)
        )
        self._teardowns.add(task)  # the loop holds tasks weakly
        task.add_done_callback(self._teardowns.discard)
        await asyncio.shield(task)

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
                # Never reap a session out from under a waiting recv().
                if sess._waiters > 0:
                    continue
                idle = now - sess.last_used
                if (sess.closed and not sess.buffer and idle > 5) or idle > self._idle:
                    doomed.append(self._sessions.pop(sid))
        await self._teardown_unregistered(doomed)

    async def shutdown(self) -> None:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        await self._teardown_unregistered(sessions)
