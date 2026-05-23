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
import re
import shlex
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
from .metrics import ACTIVE_FORWARDS, ACTIVE_SESSIONS, AUDIT_DEGRADED, Metrics
from .policy import Policy
from .redaction import redact_args
from .sessions import LocalPtyTransport, SessionRegistry
from .shelltools import build_env, run_command, run_script, spawn_argv
from .sshpool import SshPool
from .util import clamp, truncate

__all__ = ["Relay", "build_server"]

Work = Callable[[], Awaitable[tuple[str, int | None]]]
_SUDO_SEARCH_PATHS = (Path("/usr/bin/sudo"), Path("/bin/sudo"), Path("/usr/local/bin/sudo"))

# ssh_fanout: bound the per-call host count. A real production fleet
# fan-out is almost always under this limit; raise if the use case
# shows up. Without the cap a single tool call could open hundreds of
# SSH connections (each with its own credential negotiation and remote
# sshd auth log entry), turning the tool into a noisy sweep surface.
_SSH_FANOUT_MAX_HOSTS = 100

# ssh_keyscan: validate host tokens at the boundary so the eventual
# shell concatenation is safe. Hostnames (and bracketed IPv6 literals) only;
# no whitespace, no shell metacharacters, no path separators.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._\-\[\]:]+$")

# ssh_keyscan: the key types ssh-keyscan emits. Restrict to algorithms
# that appear in current OpenSSH; reject anything else at the boundary.
_ALLOWED_KEY_TYPES = frozenset({"rsa", "ecdsa", "ed25519", "dsa"})

# ssh_keyscan: cap the per-call host count so a single tool invocation
# cannot fan out thousands of outbound TCP SYNs. A real operator sweep
# is almost always well under this limit; raise if the use case shows
# up. Without the cap the tool is a free network-burst surface even at
# Tier 1.
_SSH_KEYSCAN_MAX_HOSTS = 32


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
        self.metrics = Metrics()
        # Gauges read live at scrape time: this guarantees /metrics never
        # disagrees with the underlying registries.
        self.metrics.register_gauge(ACTIVE_SESSIONS, lambda: float(self.sessions.count()))
        self.metrics.register_gauge(ACTIVE_FORWARDS, lambda: float(self.ssh.forward_count()))
        self.metrics.register_gauge(AUDIT_DEGRADED, lambda: 1.0 if self.audit.degraded else 0.0)

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
        mode = self.settings.policy_mode
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
            self.metrics.inc_tool_call(
                tool=tool, tier=int(decision.tier), mode=mode, outcome="denied"
            )
            return body

        errored = False
        try:
            body, exit_code = await work()
        except RelayError as exc:
            body, exit_code = fmt_exc(exc), None
            errored = True
        except Exception as exc:  # noqa: BLE001
            body, exit_code = fmt_exc(exc), None
            errored = True

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
        outcome = "error" if errored else "ok"
        self.metrics.inc_tool_call(tool=tool, tier=int(decision.tier), mode=mode, outcome=outcome)
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
    async def ssh_fanout(
        command: str,
        hosts: str = "",
        timeout: int = 30,
        concurrency: int = 8,
        ctx: Context | None = None,
    ) -> str:
        """Run ``command`` in parallel across hosts; per-host exit codes in one JSON.

        ``hosts`` is a comma/space-separated list, or empty to fan out across
        every entry in the resolved inventory. ``concurrency`` bounds how
        many SSH connections run at once (clamped to ``[1, 32]``). Tier is
        classified from ``command`` like a regular ``ssh_exec`` so the deny
        list and ``guarded``/``readonly`` modes see the same probe text;
        ``ssh_fanout rm -rf /`` is still Tier 3 and still refused.
        """
        # Policy text is the command itself so the existing tier
        # heuristics fire identically to ssh_exec. Construct once,
        # outside _work, so app.run() sees it before admitting.
        policy_text = command

        async def _work() -> tuple[str, int | None]:
            names = (
                [h for h in hosts.replace(",", " ").split() if h]
                if hosts.strip()
                else [h.name for h in app.inventory.hosts()]
            )
            if not names:
                return ("[no hosts configured; pass hosts= or add an inventory]", None)
            if len(names) > _SSH_FANOUT_MAX_HOSTS:
                return (
                    f"[ERROR: {len(names)} hosts exceeds the per-call cap of "
                    f"{_SSH_FANOUT_MAX_HOSTS}; split into smaller batches]",
                    None,
                )
            tmo = app.clamp_timeout(timeout)
            conc = clamp(concurrency, 1, 32)
            sem = asyncio.Semaphore(conc)

            # Aggregate output budget guides every interior `truncate`
            # call so the final serialized JSON is guaranteed to fit.
            # The top-level Relay.run() truncates this tool's return
            # value to `cfg.max_output` (clamped); if the JSON exceeds
            # that, Relay.run() appends a [TRUNCATED ...] marker which
            # turns the response into unparseable JSON. The arithmetic
            # below errs on the conservative side so that does not
            # happen even at the maximum host count and longest
            # plausible per-host output. See review on #31.
            agg_budget = app.clamp_output(cfg.max_output)
            # Cap the echoed command at a fraction of the budget so a
            # very long command alone cannot blow the envelope.
            command_budget = min(2048, agg_budget // 4)
            command_echo = truncate(command, command_budget)
            # Per-record framing reserve: compact JSON record framing
            # `{"host":"X","exit_code":N,"output":"..."}` is ~50 bytes;
            # the `truncate` marker `\n\n[TRUNCATED - X bytes total,
            # Y shown]` adds another ~50 when the output is actually
            # truncated; allow ~100 bytes of slack for JSON escape
            # expansion (e.g. embedded quotes, newlines). 200 bytes/
            # record is generous but bounded.
            per_record_overhead = 200
            # Top-level envelope: command echo + the integer fields
            # + the results array brackets + slack. 1 KiB is plenty.
            envelope_overhead = 1024 + len(command_echo) + len(names) * per_record_overhead
            remaining = max(agg_budget - envelope_overhead, 0)
            per_host_budget = max(128, remaining // max(len(names), 1))

            async def _run_one(name: str) -> dict[str, Any]:
                ck = {
                    "user": "",
                    "port": 0,
                    "key_path": "",
                    "known_hosts": "",
                    "jump": "",
                    "connect_timeout": tmo,
                }
                async with sem:
                    try:
                        out, code = await app.ssh.run(name, command, timeout=tmo, connect_kwargs=ck)
                        return {
                            "host": name,
                            "exit_code": code,
                            "output": truncate(out, per_host_budget),
                        }
                    except Exception as exc:  # noqa: BLE001
                        # codex P2 on #31: bound the exception message
                        # too, otherwise a few hosts with long error
                        # messages can blow the envelope.
                        err = truncate(
                            f"[UNREACHABLE: {exc.__class__.__name__}: {exc}]",
                            per_host_budget,
                        )
                        return {
                            "host": name,
                            "exit_code": None,
                            "output": err,
                        }

            results = await asyncio.gather(*(_run_one(n) for n in names))
            payload = {
                "command": command_echo,
                "concurrency": conc,
                "timeout": tmo,
                "host_count": len(names),
                "results": results,
            }
            # Compact JSON (no indent) so the per-record overhead
            # estimate above is realistic. Operators wanting a
            # pretty-printed view can pipe through `jq`.
            return (json.dumps(payload, default=str), None)

        return await app.run(
            tool="ssh_fanout",
            ctx=ctx,
            audit_args={
                "command": command,
                # Record the raw input so the audit reflects the actual
                # request parameters, not the resolved fallback. Copilot
                # review on #31 noted that "hosts or 'inventory'" loses
                # caller intent when the input was an empty string.
                "hosts": hosts,
                "timeout": timeout,
                "concurrency": concurrency,
            },
            policy_text=policy_text,
            max_output=app.clamp_output(cfg.max_output),
            work=_work,
        )

    @mcp.tool()
    async def ssh_keyscan(
        hosts: str,
        port: int = 22,
        key_types: str = "rsa,ecdsa,ed25519",
        timeout: int = 10,
        ctx: Context | None = None,
    ) -> str:
        """Fetch host public keys via ssh-keyscan (Tier 1, reversible).

        Opens caller-chosen outbound TCP connections to each host on
        ``port`` and reads their public host keys in known_hosts line
        format. Useful for pre-populating ``~/.ssh/known_hosts`` so a
        service account can run ``strict`` without a manual
        ``accept-new`` seeding pass.
        """

        async def _work() -> tuple[str, int | None]:
            # Validate every input *before* it reaches the shell.
            host_list = [h for h in hosts.replace(",", " ").split() if h]
            if not host_list:
                return ("[no hosts; pass hosts=<host>[,<host>...]]", None)
            # Cap the host count to bound outbound network burst. The
            # tool is operator-facing and a real production sweep is
            # almost always under 32; raise this if the use case shows
            # up. Without the cap a single call could initiate
            # thousands of SYNs to attacker-chosen destinations.
            if len(host_list) > _SSH_KEYSCAN_MAX_HOSTS:
                return (
                    f"[ERROR: {len(host_list)} hosts exceeds the per-call cap of "
                    f"{_SSH_KEYSCAN_MAX_HOSTS}; split into smaller batches]",
                    None,
                )
            for h in host_list:
                # Permitted: letters, digits, dot, dash, underscore,
                # brackets, colon (for bracketed IPv6 literals). No
                # whitespace, no shell metachars, no path separators.
                if not _HOSTNAME_RE.match(h):
                    return (
                        f"[ERROR: rejected host {h!r}: must match {_HOSTNAME_RE.pattern}]",
                        None,
                    )
            if not 1 <= port <= 65535:
                return (f"[ERROR: port {port} out of range 1..65535]", None)
            type_list = [t.strip() for t in key_types.split(",") if t.strip()]
            for t in type_list:
                if t not in _ALLOWED_KEY_TYPES:
                    return (
                        f"[ERROR: rejected key type {t!r}: "
                        f"choose from {sorted(_ALLOWED_KEY_TYPES)}]",
                        None,
                    )
            if not type_list:
                return ("[ERROR: empty key_types]", None)
            tmo = clamp(timeout, 1, 60)

            # Build the command using shlex.quote on every interpolated
            # token. Every token has also passed the regex check, but
            # quoting is defence in depth - the regex permits `-` so a
            # future loosening that admits a leading-dash hostname
            # would otherwise become an option-injection vector.
            #
            # The literal `--` separates options from positional
            # arguments so getopt-style parsing cannot interpret a host
            # that starts with `-` as a flag. ssh-keyscan accepts `--`
            # per standard POSIX option conventions.
            cmd_parts = [
                "ssh-keyscan",
                "-T",
                str(tmo),
                "-t",
                shlex.quote(",".join(type_list)),
                "-p",
                str(port),
                "--",
                *(shlex.quote(h) for h in host_list),
            ]
            cmd = " ".join(cmd_parts)
            # ssh-keyscan writes the keys to stdout and progress/error
            # messages to stderr; merge so the operator sees both.
            return await run_command(cmd, timeout=tmo, merge_stderr=True)

        return await app.run(
            tool="ssh_keyscan",
            ctx=ctx,
            audit_args={
                "hosts": hosts,
                "port": port,
                "key_types": key_types,
            },
            policy_text="",
            max_output=app.clamp_output(cfg.max_output),
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

    # --- /metrics (HTTP transport only) -------------------------------------
    #
    # FastMCP.custom_route bypasses the OAuth layer by design (the upstream
    # docstring says health-check style endpoints are intended). The audit
    # log is the source of truth; /metrics is for dashboards only and is
    # firewalled by the Caddy edge in the supported deployment.
    if cfg.transport == "http":
        from starlette.requests import Request
        from starlette.responses import Response

        @mcp.custom_route("/metrics", methods=["GET"], include_in_schema=False)
        async def _metrics(_request: Request) -> Response:
            body = app.metrics.render()
            return Response(
                content=body,
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )

    # --- MCP resources ------------------------------------------------------
    #
    # Resources are read-only context the client can list and pull on its
    # own initiative - they do NOT go through Relay.run because there is no
    # work to admit / tier / time out. Each read is still audited (tier 0,
    # tool name prefixed with "resource:") so the operator sees what context
    # the model is pulling in.

    def _audit_resource_read(name: str, body: str) -> None:
        app.audit.record(
            tool=f"resource:{name}",
            args={},
            output=body,
            exit_code=None,
            tier=0,
        )

    @mcp.resource(
        "relay-shell://inventory",
        name="inventory",
        title="Host inventory",
        description=(
            "Flat list of all hosts resolved from ~/.ssh/config and the optional "
            "RELAY_SHELL_INVENTORY file, as a JSON array of host specs. Same "
            "data shape as the ssh_hosts tool."
        ),
        mime_type="application/json",
    )
    def _resource_inventory() -> str:
        body = json.dumps([h.as_dict() for h in app.inventory.hosts()], default=str)
        _audit_resource_read("inventory", body)
        return body

    @mcp.resource(
        "relay-shell://inventory/{host}",
        name="inventory_host",
        title="Single host spec",
        description=(
            "Resolved spec for one inventory entry (or a passthrough spec the "
            "ssh layer would accept) as JSON."
        ),
        mime_type="application/json",
    )
    def _resource_inventory_host(host: str) -> str:
        spec = app.inventory.resolve(host).as_dict()
        body = json.dumps(spec, default=str)
        _audit_resource_read(f"inventory/{host}", body)
        return body

    @mcp.resource(
        "relay-shell://ssh-config",
        name="ssh_config",
        title="SSH config metadata",
        description=(
            "Path to the active ssh_config and the sorted list of non-wildcard "
            "Host aliases parsed from it, as JSON. Lets a client see what "
            "ssh_config the server is consulting without reading the file."
        ),
        mime_type="application/json",
    )
    def _resource_ssh_config() -> str:
        payload = {
            "path": app.inventory.ssh_config_file,
            "aliases": sorted(h.name for h in app.inventory.hosts() if h.source == "ssh_config"),
        }
        body = json.dumps(payload, default=str)
        _audit_resource_read("ssh-config", body)
        return body

    return mcp


_INSTRUCTIONS = """\
relay-shell - shell and SSH operations.

Local: shell_exec (one-shot), shell_script (multi-line), shell_spawn (PTY).
SSH:   ssh_exec, ssh_spawn, ssh_upload/ssh_download, ssh_forward(/list/close),
       ssh_check, ssh_hosts, ssh_keyscan (pre-populate known_hosts),
       ssh_fanout (parallel exec across a host list).
PTY sessions (local or ssh) are driven by session_send / session_recv /
session_resize / session_kill / session_list.
Diagnostics: server_info reports limits and policy mode; audit_tail
returns the last N audit records.

Every call is tier-classified, bounded (timeout + output caps), and appended
to an append-only audit log (output is hashed, never stored). Prefer
ssh_hosts/ssh_check before fleet operations.
"""
