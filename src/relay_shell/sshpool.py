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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncssh

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


class SshProcessTransport:
    """Adapts an asyncssh remote process to the session ``Transport``."""

    def __init__(self, proc: Any) -> None:
        self._p = proc

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
        with contextlib.suppress(Exception):
            self._p.terminate()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._p.wait_closed(), 5)


@dataclass
class SshPool:
    settings: Any
    inventory: Inventory
    _conns: dict[str, Any] = field(default_factory=dict)
    _forwards: dict[str, ForwardHandle] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

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

        async with self._lock:
            cached = self._conns.get(key)
            if cached is not None and not cached.is_closed():
                return cached

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

        conn = await asyncssh.connect(spec.hostname, **opts)
        if mode == "accept-new":
            await self._persist_host_key(conn, spec.hostname)

        async with self._lock:
            self._conns[key] = conn
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
        if not max_output_bytes or max_output_bytes <= 0:
            max_output_bytes = None
        try:
            if max_output_bytes is None:
                result = await asyncio.wait_for(
                    conn.run(command, check=False, encoding="utf-8", errors="replace"),
                    timeout,
                )
                out = (result.stdout or "") + (result.stderr or "")
                code = result.exit_status
                return (str(out), int(code) if isinstance(code, int) else None)
            out_parts: list[bytes] = []
            err_parts: list[bytes] = []
            out_seen = 0
            err_seen = 0

            async def _drain(stream: Any, parts: list[bytes], seen: int) -> int:
                kept = 0
                while True:
                    chunk = await stream.read(65536)
                    if not chunk:
                        return seen
                    seen += len(chunk)
                    budget = max_output_bytes - kept
                    if budget > 0:
                        piece = chunk[:budget]
                        parts.append(piece)
                        kept += len(piece)

            proc = await conn.create_process(command, encoding=None)
            out_seen, err_seen = await asyncio.wait_for(
                asyncio.gather(
                    _drain(proc.stdout, out_parts, out_seen),
                    _drain(proc.stderr, err_parts, err_seen),
                ),
                timeout,
            )
            await proc.wait_closed()
            out = b"".join(out_parts).decode("utf-8", "replace") + b"".join(err_parts).decode(
                "utf-8", "replace"
            )
            if out_seen + err_seen > max_output_bytes:
                out = truncate(out, max_output_bytes)
            code = proc.exit_status
            return (str(out), int(code) if isinstance(code, int) else None)
        except TimeoutError:
            return (f"[TIMEOUT after {timeout}s]", None)

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
        return SshProcessTransport(proc)

    async def sftp_put(
        self, target: str, local: str, remote: str, *, recurse: bool, connect_kwargs: dict[str, Any]
    ) -> str:
        conn = await self.connect(target, **connect_kwargs)
        async with conn.start_sftp_client() as sftp:
            await sftp.put(local, remote, recurse=recurse, preserve=True)
        return f"uploaded {local} -> {target}:{remote}"

    async def sftp_get(
        self, target: str, remote: str, local: str, *, recurse: bool, connect_kwargs: dict[str, Any]
    ) -> str:
        conn = await self.connect(target, **connect_kwargs)
        async with conn.start_sftp_client() as sftp:
            await sftp.get(remote, local, recurse=recurse, preserve=True)
        return f"downloaded {target}:{remote} -> {local}"

    async def add_forward(
        self, target: str, spec: str, *, connect_kwargs: dict[str, Any]
    ) -> ForwardHandle:
        conn = await self.connect(target, **connect_kwargs)
        kind, _, rest = spec.partition(":")
        kind = kind.upper().strip()
        fid = gen_id("fwd")
        if kind == "L":
            lport_s, dhost, dport_s = rest.split(":")
            listener = await conn.forward_local_port("", int(lport_s), dhost, int(dport_s))
            handle = ForwardHandle(
                fid, "local", spec, listener.get_port(), f"{dhost}:{dport_s}", listener
            )
        elif kind == "R":
            lport_s, dhost, dport_s = rest.split(":")
            listener = await conn.forward_remote_port("", int(lport_s), dhost, int(dport_s))
            handle = ForwardHandle(
                fid, "remote", spec, listener.get_port(), f"{dhost}:{dport_s}", listener
            )
        elif kind == "D":
            lport = int(rest)
            listener = await conn.forward_socks("", lport)
            handle = ForwardHandle(fid, "dynamic", spec, listener.get_port(), "socks", listener)
        else:
            raise ValueError("forward spec must start with L:, R: or D:")
        async with self._lock:
            self._forwards[fid] = handle
        return handle

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
        return f"closed forward {fid}"

    async def close_all(self) -> None:
        async with self._lock:
            forwards = list(self._forwards.values())
            conns = list(self._conns.values())
            self._forwards.clear()
            self._conns.clear()
        for handle in forwards:
            with contextlib.suppress(Exception):
                handle.listener.close()
        for conn in conns:
            with contextlib.suppress(Exception):
                conn.close()
