"""Integration tests against an in-process asyncssh server (no network).

The fixture starts an SSH server on an ephemeral loopback port with no
authentication required, an exec/shell handler, and an SFTP subsystem rooted
at a temp dir. It exercises the real :class:`SshPool` code paths.
"""

from __future__ import annotations

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
