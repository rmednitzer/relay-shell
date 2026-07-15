"""asyncssh-backed connection pool, SFTP, port forwarding, and a PTY adapter.

Connections are cached per ``user@host:port`` and reused. ``ssh_config`` is
handed to asyncssh so its full semantics (``ProxyJump``, per-host options) are
honoured; explicit arguments overlay it. ``known_hosts`` policy is explicit:
``strict`` (verify against the known_hosts file), ``ignore`` (no verification),
or ``accept-new`` (trust-on-first-use, persisted to the known_hosts file).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncssh

from .errors import ForwardError
from .inventory import HostSpec, Inventory
from .util import gen_id, truncate

__all__ = ["ForwardHandle", "SshPool", "SshProcessTransport"]

_SIG_NAMES = {2: "INT", 9: "KILL", 15: "TERM", 1: "HUP", 3: "QUIT"}
_KNOWN_HOSTS_MODES = frozenset({"strict", "accept-new", "ignore"})


def _known_hosts_path() -> str:
    return str(Path("~/.ssh/known_hosts").expanduser())


def _conn_key(host: str, user: str | None, port: int | None) -> str:
    return f"{user or ''}@{host}:{port or 22}"


def _append_known_host(hostname: str, algo: str, b64: str) -> None:
    """Synchronous known_hosts append (run off the event loop)."""
    kh = Path(_known_hosts_path())
    kh.parent.mkdir(parents=True, exist_ok=True)
    existing = kh.read_text(encoding="utf-8") if kh.is_file() else ""
    if b64 not in existing:
        with kh.open("a", encoding="utf-8") as fh:
            fh.write(f"{hostname} {algo} {b64}\n")


@dataclass
class ForwardHandle:
    id: str
    kind: str
    spec: str
    listen_port: int
    target: str
    listener: Any
    # The cached-connection entry this forward pins in use; released in
    # close_forward so the idle reaper cannot evict a connection while a
    # forward is still listening on it.
    entry: _ConnEntry | None = None


@dataclass
class _ConnEntry:
    """Cached SSH connection plus the monotonic time it was last used."""

    conn: Any
    last_used: float = field(default_factory=time.monotonic)
    # How many live holders (an ssh_spawn session, a port forward, an in-flight
    # run/transfer) are currently using this connection. The idle reaper never
    # evicts an entry with pins > 0 — the connection is in active use even if
    # nothing has re-`connect()`ed to it recently (a long-lived holder connects
    # once and drives channels directly, never refreshing the cache).
    pins: int = 0


class SshProcessTransport:
    """Adapts an asyncssh remote process to the session ``Transport``."""

    def __init__(
        self,
        proc: Any,
        *,
        pool: SshPool | None = None,
        entry: _ConnEntry | None = None,
    ) -> None:
        self._p = proc
        # The pool + cache entry backing this session's connection, pinned for
        # the session's lifetime and released in ``aclose`` (both optional so a
        # test can still build a bare transport around a fake process).
        self._pool = pool
        self._entry = entry

    async def write(self, data: bytes) -> None:
        with contextlib.suppress(Exception):
            self._p.stdin.write(data)

    def resize(self, cols: int, rows: int) -> None:
        with contextlib.suppress(Exception):
            self._p.change_terminal_size(cols, rows)

    def signal(self, sig: int) -> None:
        name = _SIG_NAMES.get(sig, "TERM")
        try:
            self._p.send_signal(name)
        except Exception:  # noqa: BLE001 - any failure -> best-effort terminate
            with contextlib.suppress(Exception):
                self._p.terminate()

    @property
    def returncode(self) -> int | None:
        rc = self._p.returncode
        return int(rc) if isinstance(rc, int) else None

    async def read_loop(self, sink: object) -> None:
        assert callable(sink)
        while True:
            data = await self._p.stdout.read(65536)
            if not data:
                return
            sink(data if isinstance(data, bytes) else str(data).encode("utf-8", "replace"))

    async def aclose(self) -> None:
        try:
            with contextlib.suppress(Exception):
                self._p.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._p.wait_closed(), 5)
        finally:
            # Release the connection pin even if terminate/wait_closed raised,
            # so a session that fails to close cleanly cannot pin its
            # connection against the idle reaper forever.
            if self._pool is not None:
                await self._pool._unpin(self._entry)


@dataclass
class SshPool:
    settings: Any
    inventory: Inventory
    _conns: dict[str, _ConnEntry] = field(default_factory=dict)
    _forwards: dict[str, ForwardHandle] = field(default_factory=dict)
    # In-flight connect() futures keyed by user@host:port so two concurrent
    # callers for the same target dedupe to a single underlying
    # ``asyncssh.connect``. Without this, both would miss the cache, both
    # would dial, and the second would silently leak the first connection.
    _pending: dict[str, asyncio.Future[Any]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def _sweep_conns(self) -> None:
        """Evict closed or idle connections from the cache.

        Mirrors the shape of ``SessionRegistry._sweep`` — opportunistic
        sweeping on every ``connect()`` rather than an always-on
        background task. ``ssh_idle_timeout=0`` disables idle eviction
        (closed connections are still purged so a re-connect attempt
        does not return a dead handle).
        """
        timeout = float(getattr(self.settings, "ssh_idle_timeout", 0) or 0)
        now = time.monotonic()
        doomed: list[Any] = []
        async with self._lock:
            for key in list(self._conns):
                entry = self._conns[key]
                try:
                    closed = entry.conn.is_closed()
                except Exception:  # noqa: BLE001 - defensive: treat as closed
                    closed = True
                # A pinned entry is in active use (a session / forward / in-flight
                # transfer holds it); never idle-evict it. A *closed* connection
                # is dead regardless of pins, so still purge it so a re-connect
                # does not return a dead handle.
                idle_evict = timeout > 0 and entry.pins == 0 and now - entry.last_used > timeout
                if closed or idle_evict:
                    doomed.append(self._conns.pop(key).conn)
        for conn in doomed:
            with contextlib.suppress(Exception):
                conn.close()

    async def _pin(self, conn: Any) -> _ConnEntry | None:
        """Pin the cached entry backing ``conn`` so the idle reaper cannot evict
        it while a caller is still using it. Returns the entry (pass it to
        :meth:`_unpin` on release) or ``None`` if ``conn`` is not the cached
        connection — a detached connection the reaper cannot touch anyway.
        """
        async with self._lock:
            for entry in self._conns.values():
                if entry.conn is conn:
                    entry.pins += 1
                    entry.last_used = time.monotonic()
                    return entry
        return None

    async def _unpin(self, entry: _ConnEntry | None) -> None:
        """Release a pin taken by :meth:`_pin` (a no-op for ``None``)."""
        if entry is None:
            return
        async with self._lock:
            if entry.pins > 0:
                entry.pins -= 1
            entry.last_used = time.monotonic()

    @contextlib.asynccontextmanager
    async def _pinned(self, conn: Any) -> AsyncIterator[None]:
        """Pin ``conn``'s cache entry for the duration of a scoped operation
        (``run`` / SFTP transfer) so a concurrent idle sweep cannot close the
        connection mid-use. Long-lived holders (sessions, forwards) pin
        explicitly instead, releasing on their own close.
        """
        entry = await self._pin(conn)
        try:
            yield
        finally:
            await self._unpin(entry)

    def _known_hosts_arg(self, mode: str) -> object:
        if mode not in _KNOWN_HOSTS_MODES:
            allowed = ", ".join(repr(v) for v in sorted(_KNOWN_HOSTS_MODES))
            raise ValueError(f"known_hosts must be one of {allowed}")
        if mode == "strict":
            return _known_hosts_path()
        # "ignore" and "accept-new" both connect without up-front verification;
        # "accept-new" additionally persists the key for future strict use.
        return None

    async def _persist_host_key(self, conn: Any, hostname: str) -> None:
        try:
            key = conn.get_server_host_key()
            blob = key.export_public_key("openssh")
            text = blob.decode() if isinstance(blob, bytes) else str(blob)
            parts = text.split()
            if len(parts) < 2:
                return
            await asyncio.to_thread(_append_known_host, hostname, parts[0], parts[1])
        except Exception:  # noqa: BLE001 - host-key persistence is best-effort
            return

    async def connect(
        self,
        target: str,
        *,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        connect_timeout: int = 0,
    ) -> Any:
        spec: HostSpec = self.inventory.resolve(target)
        eff_user = user or spec.user or ""
        eff_port = port or spec.port or 0
        eff_key = key_path or spec.identity_file or ""
        eff_jump = jump or spec.jump or ""
        mode = (known_hosts or spec.known_hosts or self.settings.ssh_known_hosts).lower()
        key = _conn_key(spec.hostname, eff_user or None, eff_port or None)

        await self._sweep_conns()
        # Cache lookup + single-flight claim happen together under the lock.
        # If another coroutine is already connecting to the same key, it
        # owns the inflight future and we await it. Otherwise we claim the
        # slot ourselves with a fresh future and do the connect outside
        # the lock so other hosts are not blocked.
        other_future: asyncio.Future[Any] | None = None
        own_future: asyncio.Future[Any] | None = None
        async with self._lock:
            entry = self._conns.get(key)
            if entry is not None and not entry.conn.is_closed():
                entry.last_used = time.monotonic()
                return entry.conn
            other_future = self._pending.get(key)
            if other_future is None:
                own_future = asyncio.get_running_loop().create_future()
                self._pending[key] = own_future
        if own_future is None:
            assert other_future is not None
            # Shield so a waiter's cancellation doesn't propagate into the
            # single-flight future and poison it for every other waiter
            # and the owner task. ``task.cancel()`` calls
            # ``self._fut_waiter.cancel()``, which without the shield
            # would cancel the shared future.
            return await asyncio.shield(other_future)

        opts: dict[str, Any] = {
            "known_hosts": self._known_hosts_arg(mode),
            "connect_timeout": connect_timeout or self.settings.ssh_connect_timeout,
        }
        if self.settings.ssh_keepalive:
            opts["keepalive_interval"] = self.settings.ssh_keepalive
        if eff_user:
            opts["username"] = eff_user
        if eff_port:
            opts["port"] = eff_port
        if eff_key:
            opts["client_keys"] = [str(Path(eff_key).expanduser())]
        if eff_jump:
            opts["tunnel"] = eff_jump
        cfg = self.inventory.ssh_config_file
        if cfg:
            opts["config"] = [cfg]

        try:
            conn = await asyncssh.connect(spec.hostname, **opts)
            if mode == "accept-new":
                await self._persist_host_key(conn, spec.hostname)
        except BaseException as exc:
            # Including CancelledError: clear the in-flight slot so a
            # subsequent caller can retry, and propagate to any waiter.
            # Only pop OUR slot — if close_all racing replaced us with a
            # fresh future for a new caller, leave that future for its
            # owner.
            async with self._lock:
                if self._pending.get(key) is own_future:
                    self._pending.pop(key, None)
            if not own_future.done():
                own_future.set_exception(exc)
            raise
        # The connect succeeded. Before caching, check whether the
        # in-flight future was cancelled out from under us (only
        # ``close_all`` does this today). If so, discard the connection
        # rather than caching it after the registry was cleared, and
        # surface the cancellation to our caller.
        if own_future.cancelled():
            with contextlib.suppress(Exception):
                conn.close()
            async with self._lock:
                if self._pending.get(key) is own_future:
                    self._pending.pop(key, None)
            raise asyncio.CancelledError("SshPool was closed while connecting")
        async with self._lock:
            self._conns[key] = _ConnEntry(conn=conn)
            if self._pending.get(key) is own_future:
                self._pending.pop(key, None)
        own_future.set_result(conn)
        return conn

    async def run(
        self,
        target: str,
        command: str,
        *,
        timeout: int,
        connect_kwargs: dict[str, Any],
        max_output_bytes: int | None = None,
    ) -> tuple[str, int | None]:
        conn = await self.connect(target, **connect_kwargs)
        # Pin for the run's duration. A run connects once and drives the channel
        # directly, so its cache entry's last_used freezes at connect time; if
        # the run outlives the idle window a concurrent connect()'s sweep would
        # otherwise evict and close the connection mid-drain. The run timeout is
        # clamped to max_timeout, but max_timeout (up to 86400) can exceed
        # ssh_idle_timeout (down to 0), so the window is not guaranteed by the
        # clamp — pin explicitly rather than rely on a cross-setting invariant.
        # Both code paths use the same explicit-create_process +
        # terminate-on-timeout cleanup so a TimeoutError never leaves a
        # remote process parked on the SSH connection. The bounded path
        # additionally caps the kept bytes; the unbounded path keeps
        # everything received.
        cap = max_output_bytes if (max_output_bytes is not None and max_output_bytes > 0) else None

        async with self._pinned(conn):
            out_parts: list[bytes] = []
            err_parts: list[bytes] = []
            out_seen = 0
            err_seen = 0
            out_kept = [0]
            err_kept = [0]

            async def _drain(stream: Any, parts: list[bytes], seen: int, kept: list[int]) -> int:
                while True:
                    chunk = await stream.read(65536)
                    if not chunk:
                        return seen
                    seen += len(chunk)
                    if cap is None:
                        parts.append(chunk)
                        kept[0] += len(chunk)
                    else:
                        budget = cap - kept[0]
                        if budget > 0:
                            piece = chunk[:budget]
                            parts.append(piece)
                            kept[0] += len(piece)

            proc: Any | None = None

            async def _open_and_drain() -> tuple[int, int]:
                # ``create_process`` is the first remote-side await: a server
                # that accepts the TCP/SSH connection but stalls on session/
                # process creation must still be bounded by ``timeout``, not
                # by waiting for the remote to ever respond. Including it in
                # the same wait_for envelope keeps ``ssh_exec(timeout=...)``
                # honest end-to-end.
                nonlocal proc
                proc = await conn.create_process(command, encoding=None)
                return await asyncio.gather(
                    _drain(proc.stdout, out_parts, out_seen, out_kept),
                    _drain(proc.stderr, err_parts, err_seen, err_kept),
                )

            try:
                out_seen, err_seen = await asyncio.wait_for(_open_and_drain(), timeout)
                # _open_and_drain set proc before returning the gather result;
                # the assert narrows the Optional for the type checker.
                assert proc is not None
                # wait_closed needs its own bound: drains hitting EOF normally
                # means the remote is exiting, but a misbehaving peer could
                # still hold the channel open. 5s is generous for a clean reap.
                await asyncio.wait_for(proc.wait_closed(), 5)
            except TimeoutError:
                # Terminate so the remote process doesn't park on the SSH
                # connection until the connection itself dies, then bound the
                # post-terminate wait so cleanup itself can't hang either.
                # ``proc`` may be None if the timeout fired during
                # create_process; in that case there is nothing local to clean up.
                if proc is not None:
                    with contextlib.suppress(Exception):
                        proc.terminate()
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(proc.wait_closed(), 2)
                return (f"[TIMEOUT after {timeout}s]", None)
            out = b"".join(out_parts).decode("utf-8", "replace") + b"".join(err_parts).decode(
                "utf-8", "replace"
            )
            if cap is not None and out_seen + err_seen > cap:
                out = truncate(out, cap)
            code = proc.exit_status
            return (str(out), int(code) if isinstance(code, int) else None)

    async def open_process(
        self,
        target: str,
        *,
        command: str,
        cols: int,
        rows: int,
        connect_kwargs: dict[str, Any],
    ) -> SshProcessTransport:
        conn = await self.connect(target, **connect_kwargs)
        proc = await conn.create_process(
            command or None,
            term_type="xterm-256color",
            term_size=(cols, rows),
            encoding=None,
        )
        # An ssh_spawn session lives indefinitely and drives the channel
        # directly (never re-connecting), so pin the connection for the
        # session's lifetime; the transport releases it in aclose().
        entry = await self._pin(conn)
        return SshProcessTransport(proc, pool=self, entry=entry)

    async def sftp_put(
        self,
        target: str,
        local: str,
        remote: str,
        *,
        recurse: bool,
        connect_kwargs: dict[str, Any],
        timeout: int = 0,
    ) -> str:
        conn = await self.connect(target, **connect_kwargs)
        # Pin for the transfer's duration: with timeout=0 an SFTP transfer is
        # bounded only by connection keepalive, so a long upload must not be
        # idle-evicted out from under itself.
        async with self._pinned(conn):
            async with conn.start_sftp_client() as sftp:
                transfer = sftp.put(local, remote, recurse=recurse, preserve=True)
                # ``timeout`` is a per-call cap on the transfer itself (the
                # connection-level keepalive is the only other bound). 0 disables
                # it. On a hung transfer wait_for cancels the in-flight put; the
                # sftp client is closed by the context manager on the way out.
                if timeout > 0:
                    try:
                        await asyncio.wait_for(transfer, timeout)
                    except TimeoutError:
                        return (
                            f"[TIMEOUT after {timeout}s] partial upload "
                            f"{local} -> {target}:{remote}"
                        )
                else:
                    await transfer
            return f"uploaded {local} -> {target}:{remote}"

    async def sftp_get(
        self,
        target: str,
        remote: str,
        local: str,
        *,
        recurse: bool,
        connect_kwargs: dict[str, Any],
        timeout: int = 0,
    ) -> str:
        conn = await self.connect(target, **connect_kwargs)
        async with self._pinned(conn):  # see sftp_put: unbounded when timeout=0
            async with conn.start_sftp_client() as sftp:
                transfer = sftp.get(remote, local, recurse=recurse, preserve=True)
                if timeout > 0:
                    try:
                        await asyncio.wait_for(transfer, timeout)
                    except TimeoutError:
                        return (
                            f"[TIMEOUT after {timeout}s] partial download "
                            f"{target}:{remote} -> {local}"
                        )
                else:
                    await transfer
            return f"downloaded {target}:{remote} -> {local}"

    @staticmethod
    def _parse_forward_spec(spec: str) -> tuple[str, int, str, int]:
        """Parse an L/R/D forward spec into (kind, listen_port, dest_host, dest_port).

        Raises a controlled ``ValueError`` (never a raw Python parse internal
        such as "invalid literal for int()" or a tuple-unpack error) on a
        malformed spec, so the message surfaced through the tool wrapper stays
        bounded (QUAL-2). ``D`` (dynamic SOCKS) has no destination; it returns
        host="" port=0.
        """
        kind, _, rest = spec.partition(":")
        kind = kind.upper().strip()
        if kind in ("L", "R"):
            try:
                lport_s, dhost, dport_s = rest.split(":")
                return kind, int(lport_s), dhost, int(dport_s)
            except ValueError:
                raise ValueError(
                    f"invalid {kind} forward spec; expected "
                    f"{kind}:<listen_port>:<dest_host>:<dest_port>"
                ) from None
        if kind == "D":
            try:
                return "D", int(rest), "", 0
            except ValueError:
                raise ValueError("invalid D forward spec; expected D:<listen_port>") from None
        raise ValueError("forward spec must start with L:, R: or D:")

    async def add_forward(
        self, target: str, spec: str, *, connect_kwargs: dict[str, Any]
    ) -> ForwardHandle:
        # Validate the spec before opening a connection: a malformed spec now
        # fails fast with a bounded message instead of connecting first and
        # then leaking a raw int()/unpack ValueError (QUAL-2).
        kind, lport, dhost, dport = self._parse_forward_spec(spec)
        # Cap active forwards (SSH-3): a persuaded client looping ssh_forward
        # would otherwise exhaust local fds / listen ports. Pre-check before
        # dialling so a saturated pool fails fast without opening anything; the
        # authoritative check under the lock below closes the listener if a
        # concurrent caller took the last slot, so the cap is never exceeded.
        cap = self.settings.max_forwards
        async with self._lock:
            if len(self._forwards) >= cap:
                raise ForwardError(
                    f"forward limit reached ({cap}); close an existing forward first"
                )
        conn = await self.connect(target, **connect_kwargs)
        # A forward listens indefinitely on the connection, so pin it for the
        # forward's lifetime (released in close_forward). Unpin on any failure
        # before the handle is tracked, so a listener error or a lost cap race
        # never leaks a pin that would keep the connection alive forever.
        entry = await self._pin(conn)
        try:
            fid = gen_id("fwd")
            if kind == "L":
                listener = await conn.forward_local_port("", lport, dhost, dport)
                handle = ForwardHandle(
                    fid, "local", spec, listener.get_port(), f"{dhost}:{dport}", listener, entry
                )
            elif kind == "R":
                listener = await conn.forward_remote_port("", lport, dhost, dport)
                handle = ForwardHandle(
                    fid, "remote", spec, listener.get_port(), f"{dhost}:{dport}", listener, entry
                )
            else:  # D (validated above)
                listener = await conn.forward_socks("", lport)
                handle = ForwardHandle(
                    fid, "dynamic", spec, listener.get_port(), "socks", listener, entry
                )
            async with self._lock:
                if len(self._forwards) >= cap:
                    with contextlib.suppress(Exception):
                        listener.close()
                        await listener.wait_closed()
                    raise ForwardError(
                        f"forward limit reached ({cap}); close an existing forward first"
                    )
                self._forwards[fid] = handle
            return handle
        except BaseException:
            await self._unpin(entry)
            raise

    def list_forwards(self) -> list[dict[str, object]]:
        return [
            {
                "id": h.id,
                "kind": h.kind,
                "spec": h.spec,
                "listen_port": h.listen_port,
                "target": h.target,
            }
            for h in self._forwards.values()
        ]

    def forward_count(self) -> int:
        """Number of currently-tracked SSH port forwards, for /metrics."""
        return len(self._forwards)

    async def close_forward(self, fid: str) -> str:
        async with self._lock:
            handle = self._forwards.pop(fid, None)
        if handle is None:
            return f"[ERROR: unknown forward: {fid}]"
        with contextlib.suppress(Exception):
            handle.listener.close()
            await handle.listener.wait_closed()
        # Release the connection pin now that this forward no longer uses it.
        await self._unpin(handle.entry)
        return f"closed forward {fid}"

    async def close_all(self) -> None:
        async with self._lock:
            forwards = list(self._forwards.values())
            entries = list(self._conns.values())
            pending = list(self._pending.values())
            self._forwards.clear()
            self._conns.clear()
            self._pending.clear()
        for fut in pending:
            if not fut.done():
                fut.cancel()
        for handle in forwards:
            with contextlib.suppress(Exception):
                handle.listener.close()
        for entry in entries:
            with contextlib.suppress(Exception):
                entry.conn.close()
