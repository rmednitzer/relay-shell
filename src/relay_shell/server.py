"""Server assembly: FastMCP instance, the audited tool runner, all tools.

Every tool runs through one path:

1. resolve request/client id from the MCP context (best-effort);
2. classify + admit via the policy layer (deny list first, always);
3. execute the work, never letting an exception reach the transport;
4. truncate to the output budget, prefix ``[exit N]`` when meaningful;
5. append one audit record (hash of the output, never the body).

This mirrors a production gateway: a tool can fail, time out, or be denied,
but it always returns a single bounded, audited string.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import pwd
import signal
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

from . import __version__
from .audit import AuditLogger
from .config import Settings, get_settings
from .errors import RelayError, fmt_exc
from .inventory import Inventory
from .policy import Policy
from .redaction import redact_args
from .sessions import LocalPtyTransport, SessionRegistry
from .shelltools import build_env, run_command, run_script, spawn_argv
from .sshpool import SshPool
from .util import clamp, truncate

__all__ = ["Relay", "build_server"]

Work = Callable[[], Awaitable[tuple[str, int | None]]]
_SUDO_SEARCH_PATHS = (Path("/usr/bin/sudo"), Path("/bin/sudo"), Path("/usr/local/bin/sudo"))


def _find_sudo_binary() -> str:
    """Return an executable sudo path from well-known locations, or ``""``.

    This is informational metadata for ``server_info`` only; command execution
    behavior does not depend on this lookup.
    """
    for path in _SUDO_SEARCH_PATHS:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return ""


def _ctx_ids(ctx: Context | None) -> tuple[str, str]:
    if ctx is None:
        return "", ""
    request_id = ""
    client_id = ""
    with contextlib.suppress(Exception):
        request_id = str(getattr(ctx, "request_id", "") or "")
    with contextlib.suppress(Exception):
        client_id = str(getattr(ctx, "client_id", "") or "")
    return request_id, client_id


class Relay:
    """Holds shared state and runs every tool through the audited path."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.audit = AuditLogger(settings.audit_path, also_stderr=settings.audit_stderr)
        self.policy = Policy(settings.policy_mode, settings.policy_deny, settings.policy_allow)
        self.inventory = Inventory(settings.ssh_config, settings.inventory).load()
        self.sessions = SessionRegistry(
            settings.max_sessions,
            settings.session_idle_timeout,
            settings.session_buffer_bytes,
        )
        self.ssh = SshPool(settings=settings, inventory=self.inventory)
        self.sudo_binary = _find_sudo_binary()

    def clamp_timeout(self, timeout: int) -> int:
        return clamp(timeout, 1, self.settings.max_timeout)

    def clamp_output(self, max_output: int) -> int:
        return clamp(max_output, 1024, self.settings.max_output_hard)

    async def run(
        self,
        *,
        tool: str,
        ctx: Context | None,
        audit_args: dict[str, Any],
        policy_text: str,
        max_output: int,
        work: Work,
    ) -> str:
        request_id, client_id = _ctx_ids(ctx)
        decision = self.policy.check(tool, policy_text)
        red = redact_args(audit_args)
        if not decision.allowed:
            body = f"[DENIED tier {int(decision.tier)} ({decision.tier.name}): {decision.reason}]"
            self.audit.record(
                tool=tool,
                args=red,
                output=body,
                exit_code=None,
                tier=int(decision.tier),
                request_id=request_id,
                client_id=client_id,
                denied=True,
            )
            return body

        try:
            body, exit_code = await work()
        except RelayError as exc:
            body, exit_code = fmt_exc(exc), None
        except Exception as exc:  # noqa: BLE001
            body, exit_code = fmt_exc(exc), None

        body = truncate(body, self.clamp_output(max_output))
        final = f"[exit {exit_code}]\n{body}" if exit_code is not None else body
        self.audit.record(
            tool=tool,
            args=red,
            output=final,
            exit_code=exit_code,
            tier=int(decision.tier),
            request_id=request_id,
            client_id=client_id,
        )
        return final

    def connect_kwargs(
        self, user: str, port: int, key_path: str, known_hosts: str, jump: str
    ) -> dict[str, Any]:
        return {
            "user": user,
            "port": port,
            "key_path": key_path,
            "known_hosts": known_hosts,
            "jump": jump,
        }


def build_server(settings: Settings | None = None) -> FastMCP:
    """Construct the FastMCP server with every tool registered."""
    cfg = settings or get_settings()
    app = Relay(cfg)

    fastmcp_kwargs: dict[str, Any] = {
        "instructions": _INSTRUCTIONS,
        "host": cfg.http_host,
        "port": cfg.http_port,
        "stateless_http": True,
        "json_response": True,
    }
    if cfg.transport == "http" and cfg.auth_enabled:
        from .auth import build_auth_settings, make_oauth_provider

        fastmcp_kwargs["auth"] = build_auth_settings(cfg.auth_issuer)
        fastmcp_kwargs["auth_server_provider"] = make_oauth_provider(cfg)

    mcp = FastMCP("relay-shell", **fastmcp_kwargs)

    # ---- local shell -------------------------------------------------------
    @mcp.tool()
    async def shell_exec(
        command: str,
        timeout: int = 60,
        max_output: int = 65536,
        cwd: str = "",
        stdin: str = "",
        merge_stderr: bool = True,
        use_shell: bool = True,
        env_json: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Run a shell command on the local host and return its combined output.

        Timeout and output size are clamped to the server limits. Set
        ``use_shell=false`` to exec an argv without a shell.
        """
        t = app.clamp_timeout(timeout)
        policy_text = "\n".join(part for part in (command, stdin, env_json) if part)
        return await app.run(
            tool="shell_exec",
            ctx=ctx,
            audit_args={
                "command": command,
                "timeout": t,
                "cwd": cwd,
                "use_shell": use_shell,
                "stdin": stdin,
                "env_json": env_json,
            },
            policy_text=policy_text,
            max_output=max_output,
            work=lambda: run_command(
                command,
                timeout=t,
                cwd=cwd,
                stdin=stdin,
                merge_stderr=merge_stderr,
                use_shell=use_shell,
                env_json=env_json,
            ),
        )

    @mcp.tool()
    async def shell_script(
        script: str,
        interpreter: str = "bash",
        strict: bool = True,
        timeout: int = 120,
        cwd: str = "",
        env_json: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Run a multi-line script (bash/sh/python) fed on stdin.

        With ``strict`` and a shell interpreter, ``set -euo pipefail`` is
        prepended so failures abort early.
        """
        t = app.clamp_timeout(timeout)
        return await app.run(
            tool="shell_script",
            ctx=ctx,
            audit_args={"interpreter": interpreter, "strict": strict, "script": script},
            policy_text=script,
            max_output=65536,
            work=lambda: run_script(
                script,
                interpreter=interpreter,
                strict=strict,
                timeout=t,
                cwd=cwd,
                env_json=env_json,
            ),
        )

    @mcp.tool()
    async def shell_spawn(
        command: str = "",
        cols: int = 120,
        rows: int = 40,
        cwd: str = "",
        env_json: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Start a persistent local PTY session; returns a session id.

        Drive it with ``session_send`` / ``session_recv``.
        """

        async def _work() -> tuple[str, int | None]:
            argv = spawn_argv(command)
            transport = await LocalPtyTransport.spawn(
                argv, cwd=cwd or None, env=build_env(env_json), cols=cols, rows=rows
            )
            sess = await app.sessions.add(
                kind="local",
                title=" ".join(argv),
                transport=transport,
                cols=cols,
                rows=rows,
            )
            return (
                f"session {sess.id} started ({' '.join(argv)}); "
                f"use session_recv/session_send with this id",
                None,
            )

        return await app.run(
            tool="shell_spawn",
            ctx=ctx,
            audit_args={"command": command or "/bin/bash", "size": f"{cols}x{rows}"},
            policy_text=command,
            max_output=4096,
            work=_work,
        )

    # ---- ssh ---------------------------------------------------------------
    @mcp.tool()
    async def ssh_exec(
        host: str,
        command: str,
        timeout: int = 60,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Run a command on a remote host over SSH and return its output.

        ``host`` may be an inventory/ssh_config alias or ``user@host``.
        ``known_hosts`` is ``strict`` | ``accept-new`` | ``ignore``.
        """
        t = app.clamp_timeout(timeout)
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)
        return await app.run(
            tool="ssh_exec",
            ctx=ctx,
            audit_args={"host": host, "command": command, "timeout": t, "jump": jump},
            policy_text=command,
            max_output=65536,
            work=lambda: app.ssh.run(host, command, timeout=t, connect_kwargs=ck),
        )

    @mcp.tool()
    async def ssh_spawn(
        host: str,
        command: str = "",
        cols: int = 120,
        rows: int = 40,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Open a persistent interactive PTY on a remote host; returns a session id."""
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)

        async def _work() -> tuple[str, int | None]:
            transport = await app.ssh.open_process(
                host, command=command, cols=cols, rows=rows, connect_kwargs=ck
            )
            sess = await app.sessions.add(
                kind="ssh",
                title=f"ssh {host}: {command or 'shell'}",
                transport=transport,
                cols=cols,
                rows=rows,
            )
            return (f"session {sess.id} started (ssh {host}); use session_recv/session_send", None)

        return await app.run(
            tool="ssh_spawn",
            ctx=ctx,
            audit_args={"host": host, "command": command or "shell", "size": f"{cols}x{rows}"},
            policy_text=command,
            max_output=4096,
            work=_work,
        )

    # ---- sessions ----------------------------------------------------------
    @mcp.tool()
    async def session_send(
        session_id: str, data: str, enter: bool = True, ctx: Context | None = None
    ) -> str:
        """Send input to a session (local or SSH). ``enter`` appends a newline."""

        async def _work() -> tuple[str, int | None]:
            payload = data + ("\n" if enter else "")
            await app.sessions.send(session_id, payload.encode("utf-8"))
            return (f"sent {len(payload)} bytes to {session_id}", None)

        return await app.run(
            tool="session_send",
            ctx=ctx,
            audit_args={"session_id": session_id, "data": data, "enter": enter},
            policy_text=data,
            max_output=2048,
            work=_work,
        )

    @mcp.tool()
    async def session_recv(
        session_id: str,
        timeout: float = 2.0,
        max_bytes: int = 65536,
        ctx: Context | None = None,
    ) -> str:
        """Read buffered/new output from a session, waiting up to ``timeout`` seconds."""

        async def _work() -> tuple[str, int | None]:
            tmo = max(0.0, min(float(timeout), 60.0))
            mb = clamp(max_bytes, 256, app.settings.max_output_hard)
            return (await app.sessions.recv(session_id, tmo, mb), None)

        return await app.run(
            tool="session_recv",
            ctx=ctx,
            audit_args={"session_id": session_id, "timeout": timeout},
            policy_text="",
            max_output=max_bytes,
            work=_work,
        )

    @mcp.tool()
    async def session_resize(
        session_id: str, cols: int, rows: int, ctx: Context | None = None
    ) -> str:
        """Resize a session's PTY."""

        async def _work() -> tuple[str, int | None]:
            await app.sessions.resize(session_id, max(1, cols), max(1, rows))
            return (f"resized {session_id} to {cols}x{rows}", None)

        return await app.run(
            tool="session_resize",
            ctx=ctx,
            audit_args={"session_id": session_id, "cols": cols, "rows": rows},
            policy_text="",
            max_output=512,
            work=_work,
        )

    @mcp.tool()
    async def session_kill(
        session_id: str,
        signal_name: str = "TERM",
        close: bool = True,
        ctx: Context | None = None,
    ) -> str:
        """Signal a session and (by default) close and reap it."""

        async def _work() -> tuple[str, int | None]:
            name = signal_name.upper()
            if name.startswith("SIG"):
                name = name[3:]
            try:
                sig = int(getattr(signal, f"SIG{name}"))
            except (AttributeError, ValueError):
                sig = int(signal.SIGTERM)
            await app.sessions.kill(session_id, sig)
            if close:
                await app.sessions.close(session_id)
                return (f"killed and closed {session_id}", None)
            return (f"sent SIG{name} to {session_id}", None)

        return await app.run(
            tool="session_kill",
            ctx=ctx,
            audit_args={"session_id": session_id, "signal": signal_name, "close": close},
            policy_text="",
            max_output=512,
            work=_work,
        )

    @mcp.tool()
    async def session_list(ctx: Context | None = None) -> str:
        """List active sessions with size, age, idle, and byte counters."""

        async def _work() -> tuple[str, int | None]:
            rows = await app.sessions.list()
            return (json.dumps(rows, indent=2) if rows else "[]", None)

        return await app.run(
            tool="session_list",
            ctx=ctx,
            audit_args={},
            policy_text="",
            max_output=65536,
            work=_work,
        )

    # ---- ssh transfer / forwarding ----------------------------------------
    @mcp.tool()
    async def ssh_upload(
        host: str,
        local_path: str,
        remote_path: str,
        recursive: bool = False,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Upload a file or tree to a remote host via SFTP."""
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)

        async def _work() -> tuple[str, int | None]:
            msg = await app.ssh.sftp_put(
                host, local_path, remote_path, recurse=recursive, connect_kwargs=ck
            )
            return (msg, None)

        return await app.run(
            tool="ssh_upload",
            ctx=ctx,
            audit_args={"host": host, "local": local_path, "remote": remote_path},
            policy_text=f"upload {local_path} {host}:{remote_path}",
            max_output=2048,
            work=_work,
        )

    @mcp.tool()
    async def ssh_download(
        host: str,
        remote_path: str,
        local_path: str,
        recursive: bool = False,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Download a file or tree from a remote host via SFTP."""
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)

        async def _work() -> tuple[str, int | None]:
            msg = await app.ssh.sftp_get(
                host, remote_path, local_path, recurse=recursive, connect_kwargs=ck
            )
            return (msg, None)

        return await app.run(
            tool="ssh_download",
            ctx=ctx,
            audit_args={"host": host, "remote": remote_path, "local": local_path},
            policy_text=f"download {host}:{remote_path} {local_path}",
            max_output=2048,
            work=_work,
        )

    @mcp.tool()
    async def ssh_forward(
        host: str,
        spec: str,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Create a port forward.

        Spec: ``L:lport:dhost:dport`` (local), ``R:rport:dhost:dport``
        (remote), or ``D:lport`` (dynamic SOCKS).
        """
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)

        async def _work() -> tuple[str, int | None]:
            handle = await app.ssh.add_forward(host, spec, connect_kwargs=ck)
            return (
                f"forward {handle.id} active: {handle.kind} {spec} "
                f"listening on port {handle.listen_port}",
                None,
            )

        return await app.run(
            tool="ssh_forward",
            ctx=ctx,
            audit_args={"host": host, "spec": spec},
            policy_text=f"forward {spec}",
            max_output=1024,
            work=_work,
        )

    @mcp.tool()
    async def ssh_forward_list(ctx: Context | None = None) -> str:
        """List active SSH port forwards."""

        async def _work() -> tuple[str, int | None]:
            rows = app.ssh.list_forwards()
            return (json.dumps(rows, indent=2) if rows else "[]", None)

        return await app.run(
            tool="ssh_forward_list",
            ctx=ctx,
            audit_args={},
            policy_text="",
            max_output=8192,
            work=_work,
        )

    @mcp.tool()
    async def ssh_forward_close(forward_id: str, ctx: Context | None = None) -> str:
        """Close an SSH port forward by id."""

        async def _work() -> tuple[str, int | None]:
            return (await app.ssh.close_forward(forward_id), None)

        return await app.run(
            tool="ssh_forward_close",
            ctx=ctx,
            audit_args={"forward_id": forward_id},
            policy_text="",
            max_output=512,
            work=_work,
        )

    @mcp.tool()
    async def ssh_check(hosts: str = "", timeout: int = 5, ctx: Context | None = None) -> str:
        """Probe connectivity to the given hosts (or the whole inventory)."""

        async def _work() -> tuple[str, int | None]:
            names = (
                [h for h in hosts.replace(",", " ").split() if h]
                if hosts.strip()
                else [h.name for h in app.inventory.hosts()]
            )
            if not names:
                return ("[no hosts configured; pass hosts= or add an inventory]", None)
            tmo = clamp(timeout, 1, 60)
            lines: list[str] = []
            for name in names:
                ck: dict[str, Any] = {
                    "user": "",
                    "port": 0,
                    "key_path": "",
                    "known_hosts": "",
                    "jump": "",
                    "connect_timeout": tmo,
                }
                try:
                    out, code = await app.ssh.run(name, "echo ok", timeout=tmo, connect_kwargs=ck)
                    ok = code == 0 and "ok" in out
                    lines.append(f"{name}: {'ok' if ok else 'UNREACHABLE'}")
                except Exception as exc:  # noqa: BLE001
                    lines.append(f"{name}: UNREACHABLE ({exc.__class__.__name__})")
            return ("\n".join(lines), None)

        return await app.run(
            tool="ssh_check",
            ctx=ctx,
            audit_args={"hosts": hosts or "inventory"},
            policy_text="",
            max_output=8192,
            work=_work,
        )

    @mcp.tool()
    async def ssh_hosts(ctx: Context | None = None) -> str:
        """Show the resolved host inventory (ssh_config + inventory file)."""

        async def _work() -> tuple[str, int | None]:
            rows = [h.as_dict() for h in app.inventory.hosts()]
            return (json.dumps(rows, indent=2) if rows else "[]", None)

        return await app.run(
            tool="ssh_hosts",
            ctx=ctx,
            audit_args={},
            policy_text="",
            max_output=32768,
            work=_work,
        )

    @mcp.tool()
    async def server_info(ctx: Context | None = None) -> str:
        """Report version, effective limits, policy mode, and audit status."""

        async def _work() -> tuple[str, int | None]:
            uid = os.getuid()
            euid = os.geteuid()
            user = ""
            with contextlib.suppress(KeyError):
                user = pwd.getpwuid(euid).pw_name
            info = {
                "name": "relay-shell",
                "version": __version__,
                "transport": cfg.transport,
                "policy_mode": cfg.policy_mode,
                "runtime": {
                    "uid": uid,
                    "euid": euid,
                    "user": user,
                    "is_root": euid == 0,
                    "sudo_binary": app.sudo_binary,
                },
                "limits": {
                    "default_timeout": cfg.default_timeout,
                    "max_timeout": cfg.max_timeout,
                    "max_output": cfg.max_output,
                    "max_output_hard": cfg.max_output_hard,
                    "max_sessions": cfg.max_sessions,
                },
                "audit": {"path": app.audit.path, "degraded": app.audit.degraded},
                "ssh": {
                    "known_hosts_default": cfg.ssh_known_hosts,
                    "inventory_hosts": len(app.inventory.hosts()),
                    "ssh_config": app.inventory.ssh_config_file,
                },
            }
            return (json.dumps(info, indent=2), None)

        return await app.run(
            tool="server_info",
            ctx=ctx,
            audit_args={},
            policy_text="",
            max_output=4096,
            work=_work,
        )

    @mcp.tool()
    async def audit_tail(lines: int = 50, ctx: Context | None = None) -> str:
        """Return the last N records from the audit log (Tier 0, read-only)."""
        # Clamp to a generous but bounded ceiling so a misconfigured client
        # cannot ask for the whole log. The output budget on the wrapper is
        # the second line of defence: even at 1000 lines x worst-case
        # record size, the bound truncates rather than the response
        # blowing the transport.
        bounded = clamp(lines, 1, 1000)

        async def _work() -> tuple[str, int | None]:
            # File read is blocking; offload so the event loop stays free.
            body = await asyncio.to_thread(app.audit.tail, bounded)
            return body, None

        return await app.run(
            tool="audit_tail",
            ctx=ctx,
            audit_args={"lines": bounded},
            policy_text="",
            max_output=app.clamp_output(cfg.max_output),
            work=_work,
        )

    return mcp


_INSTRUCTIONS = """\
relay-shell - shell and SSH operations.

Local: shell_exec (one-shot), shell_script (multi-line), shell_spawn (PTY).
SSH:   ssh_exec, ssh_spawn, ssh_upload/ssh_download, ssh_forward(/list/close),
       ssh_check, ssh_hosts.
PTY sessions (local or ssh) are driven by session_send / session_recv /
session_resize / session_kill / session_list.
Diagnostics: server_info for limits and policy mode, audit_tail for the
last N audit records.

Every call is tier-classified, bounded (timeout + output caps), and appended
to an append-only audit log (output is hashed, never stored). Prefer
ssh_hosts/ssh_check before fleet operations.
"""
