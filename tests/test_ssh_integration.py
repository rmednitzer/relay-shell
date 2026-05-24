"""Integration tests against an in-process asyncssh server (no network).

The fixture starts an SSH server on an ephemeral loopback port with no
authentication required, an exec/shell handler, and an SFTP subsystem rooted
at a temp dir. It exercises the real :class:`SshPool` code paths.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import asyncssh
import pytest

from relay_shell.config import Settings
from relay_shell.inventory import Inventory
from relay_shell.sessions import SessionRegistry
from relay_shell.sshpool import SshPool


class _NoAuthServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return False  # no authentication required


class _ForwardServer(_NoAuthServer):
    """SSH server that accepts both direct-tcpip and tcpip-forward channels."""

    def connection_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> bool:
        return True  # allow L: (direct-tcpip) and D: (SOCKS-relayed) forwards

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        return True  # allow R: (tcpip-forward) forwards


async def _handle(process: Any) -> None:
    command = process.command
    if command is None:
        process.stdout.write("shell-ready\n")
        async for line in process.stdin:
            if line.strip() == "quit":
                break
            process.stdout.write("echo:" + line)
        process.exit(0)
        return
    if command.strip() == "echo ok":
        process.stdout.write("ok\n")
        process.exit(0)
    elif command.strip().startswith("echo "):
        process.stdout.write(command.strip()[5:] + "\n")
        process.exit(0)
    elif command.strip() == "hang":
        # Used by the timeout test: never returns until killed.
        await asyncio.sleep(60)
        process.exit(0)
    else:
        process.stderr.write("unsupported\n")
        process.exit(3)


@pytest.fixture
async def ssh_port(tmp_path: Path) -> AsyncIterator[int]:
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    remote_root = tmp_path / "remote"
    remote_root.mkdir()

    def _sftp(chan: Any) -> Any:
        return asyncssh.SFTPServer(chan, chroot=str(remote_root))

    server = await asyncssh.create_server(
        _NoAuthServer,
        "127.0.0.1",
        0,
        server_host_keys=[host_key],
        process_factory=_handle,
        sftp_factory=_sftp,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


def _pool(tmp_path: Path) -> SshPool:
    settings = Settings(
        audit_path=str(tmp_path / "a.jsonl"),
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=0,
        ssh_config=str(tmp_path / "none"),
    )
    inv = Inventory(settings.ssh_config, "").load()
    return SshPool(settings=settings, inventory=inv)


def _ck(port: int) -> dict[str, Any]:
    return {"user": "tester", "port": port, "key_path": "", "known_hosts": "ignore", "jump": ""}


async def test_ssh_exec_ok(ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        out, code = await pool.run(
            "127.0.0.1", "echo hello", timeout=10, connect_kwargs=_ck(ssh_port)
        )
        assert code == 0
        assert "hello" in out
    finally:
        await pool.close_all()


async def test_ssh_exec_nonzero(ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        out, code = await pool.run("127.0.0.1", "doomed", timeout=10, connect_kwargs=_ck(ssh_port))
        assert code == 3
        assert "unsupported" in out
    finally:
        await pool.close_all()


async def test_ssh_connection_is_reused(ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        c1 = await pool.connect("127.0.0.1", **_ck(ssh_port))
        c2 = await pool.connect("127.0.0.1", **_ck(ssh_port))
        assert c1 is c2
    finally:
        await pool.close_all()


async def test_ssh_connect_rejects_invalid_known_hosts_mode(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        with pytest.raises(ValueError, match="known_hosts must be one of"):
            await pool.connect(
                "127.0.0.1",
                user="tester",
                port=22,
                key_path="",
                known_hosts="invalid-mode",
                jump="",
            )
    finally:
        await pool.close_all()


async def test_sftp_put_and_get(ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    local = tmp_path / "local"
    local.mkdir()
    src = local / "a.txt"
    src.write_text("payload-xyz", encoding="utf-8")
    try:
        msg = await pool.sftp_put(
            "127.0.0.1", str(src), "uploaded.txt", recurse=False, connect_kwargs=_ck(ssh_port)
        )
        assert "uploaded" in msg
        assert (tmp_path / "remote" / "uploaded.txt").read_text() == "payload-xyz"

        dst = local / "back.txt"
        await pool.sftp_get(
            "127.0.0.1", "uploaded.txt", str(dst), recurse=False, connect_kwargs=_ck(ssh_port)
        )
        assert dst.read_text() == "payload-xyz"
    finally:
        await pool.close_all()


async def test_ssh_pty_session(ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    reg = SessionRegistry(8, 60, 65536)
    try:
        tr = await pool.open_process(
            "127.0.0.1", command="", cols=80, rows=24, connect_kwargs=_ck(ssh_port)
        )
        sess = await reg.add(kind="ssh", title="t", transport=tr, cols=80, rows=24)
        banner = ""
        for _ in range(10):
            banner += await reg.recv(sess.id, timeout=0.5, max_bytes=4096)
            if "shell-ready" in banner:
                break
        assert "shell-ready" in banner
        await reg.send(sess.id, b"hello\n")
        echoed = ""
        for _ in range(10):
            echoed += await reg.recv(sess.id, timeout=0.5, max_bytes=4096)
            if "echo:hello" in echoed:
                break
        assert "echo:hello" in echoed
    finally:
        await reg.shutdown()
        await pool.close_all()


# ---------------------------------------------------------------------------
# Fault injection + uncovered code paths (backlog B-022)
# ---------------------------------------------------------------------------


@pytest.fixture
async def forward_ssh_port(tmp_path: Path) -> AsyncIterator[int]:
    """SSH server that accepts both inbound and outbound forwarding requests."""
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        _ForwardServer,
        "127.0.0.1",
        0,
        server_host_keys=[host_key],
        process_factory=_handle,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


async def test_ssh_run_timeout(ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        out, code = await pool.run("127.0.0.1", "hang", timeout=1, connect_kwargs=_ck(ssh_port))
        assert code is None
        assert "[TIMEOUT after 1s]" in out
    finally:
        await pool.close_all()


async def test_ssh_transport_resize_signal(ssh_port: int, tmp_path: Path) -> None:
    """Exercise SshProcessTransport.resize and .signal on a live process."""
    pool = _pool(tmp_path)
    try:
        tr = await pool.open_process(
            "127.0.0.1", command="", cols=80, rows=24, connect_kwargs=_ck(ssh_port)
        )
        # Both are best-effort and must not raise.
        tr.resize(120, 40)
        tr.signal(15)  # SIGTERM -> mapped to "TERM"
        tr.signal(99)  # unmapped -> falls back to "TERM"
        await tr.aclose()
    finally:
        await pool.close_all()


async def test_ssh_forward_local(forward_ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        handle = await pool.add_forward(
            "127.0.0.1",
            "L:0:127.0.0.1:80",
            connect_kwargs=_ck(forward_ssh_port),
        )
        assert handle.kind == "local"
        assert handle.target == "127.0.0.1:80"
        assert handle.listen_port > 0

        forwards = pool.list_forwards()
        assert len(forwards) == 1
        assert forwards[0]["id"] == handle.id
        assert forwards[0]["kind"] == "local"
        assert pool.forward_count() == 1

        msg = await pool.close_forward(handle.id)
        assert "closed forward" in msg
        assert pool.forward_count() == 0
    finally:
        await pool.close_all()


async def test_ssh_forward_remote(forward_ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        handle = await pool.add_forward(
            "127.0.0.1",
            "R:0:127.0.0.1:80",
            connect_kwargs=_ck(forward_ssh_port),
        )
        assert handle.kind == "remote"
        assert handle.target == "127.0.0.1:80"
    finally:
        await pool.close_all()


async def test_ssh_forward_dynamic(forward_ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        handle = await pool.add_forward("127.0.0.1", "D:0", connect_kwargs=_ck(forward_ssh_port))
        assert handle.kind == "dynamic"
        assert handle.target == "socks"
        assert handle.listen_port > 0
    finally:
        await pool.close_all()


async def test_ssh_forward_invalid_kind(forward_ssh_port: int, tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    try:
        with pytest.raises(ValueError, match="forward spec must start with"):
            await pool.add_forward("127.0.0.1", "X:0:foo:80", connect_kwargs=_ck(forward_ssh_port))
    finally:
        await pool.close_all()


async def test_ssh_close_forward_unknown_id_returns_error(
    forward_ssh_port: int, tmp_path: Path
) -> None:
    pool = _pool(tmp_path)
    try:
        msg = await pool.close_forward("fwd-does-not-exist")
        assert "ERROR" in msg
        assert "unknown forward" in msg
    finally:
        await pool.close_all()


async def test_ssh_accept_new_persists_host_key(
    ssh_port: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """accept-new mode appends the server host key to ~/.ssh/known_hosts."""
    monkeypatch.setenv("HOME", str(tmp_path))
    kh = tmp_path / ".ssh" / "known_hosts"
    assert not kh.exists()

    pool = _pool(tmp_path)
    try:
        out, code = await pool.run(
            "127.0.0.1",
            "echo ok",
            timeout=5,
            connect_kwargs={
                "user": "tester",
                "port": ssh_port,
                "key_path": "",
                "known_hosts": "accept-new",
                "jump": "",
            },
        )
        assert code == 0
        assert "ok" in out
        assert kh.is_file()
        content = kh.read_text(encoding="utf-8")
        # Persisted line is "<hostname> <algo> <b64>"; algo for our test key is ed25519.
        assert "ssh-ed25519" in content
        assert "127.0.0.1" in content

        # A second connection in the same mode must not duplicate the line.
        await pool.close_all()
        pool2 = _pool(tmp_path)
        try:
            await pool2.run(
                "127.0.0.1",
                "echo ok",
                timeout=5,
                connect_kwargs={
                    "user": "tester",
                    "port": ssh_port,
                    "key_path": "",
                    "known_hosts": "accept-new",
                    "jump": "",
                },
            )
            assert kh.read_text(encoding="utf-8").count("ssh-ed25519") == 1
        finally:
            await pool2.close_all()
    finally:
        await pool.close_all()


async def test_ssh_strict_mode_resolves_known_hosts_path(tmp_path: Path) -> None:
    """strict mode reports the known_hosts file path through _known_hosts_arg."""
    pool = _pool(tmp_path)
    try:
        arg = pool._known_hosts_arg("strict")
        assert isinstance(arg, str)
        assert arg.endswith("known_hosts")
        # ignore and accept-new both return None (no upfront verification).
        assert pool._known_hosts_arg("ignore") is None
        assert pool._known_hosts_arg("accept-new") is None
    finally:
        await pool.close_all()


async def test_ssh_connect_options_keepalive_and_ssh_config(ssh_port: int, tmp_path: Path) -> None:
    """connect() applies keepalive_interval and ssh_config when set."""
    cfg = tmp_path / "ssh_config"
    cfg.write_text("Host 127.0.0.1\n  StrictHostKeyChecking no\n", encoding="utf-8")
    settings = Settings(
        audit_path=str(tmp_path / "a.jsonl"),
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=15,  # exercise line 158
        ssh_config=str(cfg),  # exercise line 169
    )
    inv = Inventory(settings.ssh_config, "").load()
    pool = SshPool(settings=settings, inventory=inv)
    try:
        out, code = await pool.run("127.0.0.1", "echo ok", timeout=5, connect_kwargs=_ck(ssh_port))
        assert code == 0
        assert "ok" in out
    finally:
        await pool.close_all()


async def test_ssh_connect_options_key_path(ssh_port: int, tmp_path: Path) -> None:
    """connect() expands and forwards a client key path."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = tmp_path / "id_test"
    key_path.write_bytes(key.export_private_key())
    key_path.chmod(0o600)

    pool = _pool(tmp_path)
    try:
        out, code = await pool.run(
            "127.0.0.1",
            "echo ok",
            timeout=5,
            connect_kwargs={
                "user": "tester",
                "port": ssh_port,
                "key_path": str(key_path),  # exercise line 164
                "known_hosts": "ignore",
                "jump": "",
            },
        )
        assert code == 0
        assert "ok" in out
    finally:
        await pool.close_all()


async def test_ssh_close_all_drops_forwards(forward_ssh_port: int, tmp_path: Path) -> None:
    """close_all() must release every cached connection and tracked forward."""
    pool = _pool(tmp_path)
    handle = await pool.add_forward(
        "127.0.0.1", "L:0:127.0.0.1:80", connect_kwargs=_ck(forward_ssh_port)
    )
    assert pool.forward_count() == 1
    assert handle.listen_port > 0
    await pool.close_all()
    assert pool.forward_count() == 0
    assert pool.list_forwards() == []
