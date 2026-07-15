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
import ipaddress
import json
import logging
import os
import pwd
import re
import shlex
import signal
import socket
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

from . import __version__, seccomp
from .audit import AuditLogger
from .broker import ConfirmationBroker
from .config import Settings, get_settings
from .errors import RelayError, fmt_exc
from .inventory import Inventory
from .metrics import ACTIVE_FORWARDS, ACTIVE_SESSIONS, AUDIT_DEGRADED, Metrics
from .policy import Policy, Tier
from .redaction import redact_args
from .sessions import LocalPtyTransport, Session, SessionRegistry, Transport
from .shelltools import build_env, run_command, run_script, spawn_argv
from .sshpool import SshPool
from .util import clamp, sha256_hex, truncate

__all__ = ["Relay", "build_server"]

_log = logging.getLogger("relay_shell.server")

Work = Callable[[], Awaitable[tuple[str, int | None]]]
_SUDO_SEARCH_PATHS = (Path("/usr/bin/sudo"), Path("/bin/sudo"), Path("/usr/local/bin/sudo"))

# ssh_fanout: bound the per-call host count. A real production fleet
# fan-out is almost always under this limit; raise if the use case
# shows up. Without the cap a single tool call could open hundreds of
# SSH connections (each with its own credential negotiation and remote
# sshd auth log entry), turning the tool into a noisy sweep surface.
_SSH_FANOUT_MAX_HOSTS = 100

# ssh_check: like ssh_fanout, cap the per-call host count and bound how many
# probes run at once (SSH-2). Without the cap the inventory-wide default could
# fan a large fleet into one call; without bounded concurrency the probes ran
# strictly sequentially, so a big list multiplied by the connect timeout into a
# long-blocking call. The probe is read-only ("echo ok"); output order follows
# the input list regardless of completion order.
_SSH_CHECK_MAX_HOSTS = 100
_SSH_CHECK_CONCURRENCY = 8

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


def _confirm_op_key(policy_text: str, audit_args: dict[str, Any]) -> str:
    """Full operation identity for the Tier-3 confirmation broker (ADR 0009).

    A confirmation token must authorize the *exact* call, so the key binds both
    the command/content the executor runs (``policy_text``) **and** a canonical
    serialization of every audited argument. ``audit_args`` carries the
    operation's *target* - the ``host`` for the SSH tools, ``hosts`` for
    ``ssh_fanout``, ``cwd`` for the shell tools, ``session_id`` for
    ``session_send``, ``local``/``remote`` for the transfer tools - which
    ``policy_text`` deliberately omits (it is the command-content probe the deny
    list and tier classifier see). Binding to both closes the confused-deputy
    gap where a token armed for one target could be consumed against another
    (e.g. confirm ``cwd=/tmp`` then execute ``cwd=/``, or confirm one host then
    fan out to the whole inventory). The raw (un-redacted) args are used so
    redaction never collapses two distinct operations to the same key; the key
    is only hashed for the token binding, never logged.
    """
    canonical = json.dumps(
        audit_args, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
    )
    return f"{policy_text}\x00{canonical}"


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


# --- policy_text builders (runbook R-002) ------------------------------------
#
# The admission contract is: every byte the executor will see, the policy
# layer sees first (deny list, then the tier heuristics). Each tool with a
# non-empty policy surface builds its probe text through exactly one function
# here, so the contract is greppable per tool and pinned by
# tests/test_tool_wrappers.py::test_policy_text_builders_*. A tool wrapper
# never assembles policy text inline.


def _policy_text_shell_exec(command: str, stdin: str, env_json: str) -> str:
    """The command line, its stdin, and the env overlay (LD_PRELOAD, PATH...)."""
    return "\n".join(part for part in (command, stdin, env_json) if part)


def _policy_text_shell_script(script: str, env_json: str) -> str:
    """The script body (it becomes the interpreter's stdin) and the env overlay."""
    return "\n".join(part for part in (script, env_json) if part)


def _policy_text_shell_spawn(command: str, env_json: str) -> str:
    """The spawned command and the env overlay shaping the PTY's environment."""
    return "\n".join(part for part in (command, env_json) if part)


# The SSH command tools fold the *destination host* into the deny probe (F2),
# closing the asymmetry with the transfer tools: `RELAY_SHELL_POLICY_DENY` is
# the documented way to block an SSH tool from reaching a host (e.g. the cloud
# metadata IP), and it must work for the tools that grant remote execution, not
# only for upload/download/forward/keyscan. Widened with the host's canonical IP
# forms (SSRF-1/2). Tradeoff (SEC-1, accepted): the tier classifier also sees
# the host, so a host embedding a destructive word at a token start
# over-classifies (bites only `guarded`; `RELAY_SHELL_POLICY_ALLOW` is the
# escape hatch). The command stays first so its tier tokens classify as before.
def _policy_text_ssh_exec(host: str, command: str) -> str:
    """The remote command line plus the destination host, for the deny list."""
    return _with_canonical_ips(f"{command}\n{host}", host)


def _policy_text_ssh_spawn(host: str, command: str) -> str:
    """The remote command (empty = login shell) plus the destination host."""
    return _with_canonical_ips(f"{command}\n{host}", host)


def _policy_text_ssh_fanout(hosts: str, command: str) -> str:
    """The fanned-out command plus every target host, for the deny list.

    ``hosts`` is a comma/space-separated list; each token is canonical-IP
    widened (SSRF-1) like ``ssh_keyscan`` so a fleet target cannot dodge an IP
    deny by an alternate spelling.
    """
    tokens = [t for t in hosts.replace(",", " ").split() if t]
    return _with_canonical_ips(f"{command}\n{hosts}", *tokens)


def _policy_text_ssh_check(hosts: str) -> str:
    """The probed host list, for the deny list (F2).

    ``ssh_check`` is Tier 0, so folding the hosts in does not change tier
    classification (it stays read-only) — it only lets `RELAY_SHELL_POLICY_DENY`
    gate which hosts may be probed, matching the other SSH tools.
    """
    tokens = [t for t in hosts.replace(",", " ").split() if t]
    return _with_canonical_ips(hosts, *tokens)


def _policy_text_session_send(data: str) -> str:
    """The bytes written to the session's PTY (before the optional newline)."""
    return data


def _policy_text_ssh_upload(host: str, local_path: str, remote_path: str) -> str:
    """A synthetic ``upload`` phrase naming both endpoints, for the deny list.

    Widened with the canonical IP of ``host`` (SSRF-2) so an IP deny is not
    dodged by a decimal/hex/octal/IPv4-mapped spelling of the destination.
    """
    return _with_canonical_ips(f"upload {local_path} {host}:{remote_path}", host)


def _policy_text_ssh_download(host: str, remote_path: str, local_path: str) -> str:
    """A synthetic ``download`` phrase naming both endpoints, for the deny list.

    Widened with the canonical IP of ``host`` (SSRF-2), as in ``ssh_upload``.
    """
    return _with_canonical_ips(f"download {host}:{remote_path} {local_path}", host)


def _policy_text_ssh_forward(spec: str) -> str:
    """A synthetic ``forward`` phrase carrying the spec, for the deny list.

    Widened with the canonical IP of the forward's destination host (SSRF-2):
    an ``L:/R:`` forward dials ``dhost``, so an IP deny on, say, the cloud
    metadata address should catch it however the caller spelled it.
    """
    return _with_canonical_ips(f"forward {spec}", _forward_dhost(spec))


def _canonical_ips(token: str) -> list[str]:
    """Canonical IP form(s) a *literal-IP* host token encodes (no DNS).

    SSRF-1: ``RELAY_SHELL_POLICY_DENY`` matches the probe *text*, so a caller
    can dodge an IP-based deny by spelling the same address another way the OS
    resolver still accepts — decimal (``2130706433``), hex (``0x7f000001`` /
    ``0x7f.0.0.1``), octal (``0177.0.0.1``), dotted-short (``127.1``), or
    IPv4-mapped IPv6 (``::ffff:127.0.0.1``). This returns the canonical
    dotted/colon form(s) of any literal IP a token encodes so the caller can
    append them to the probe and an operator's IP deny catches every spelling.

    Hostnames return ``[]``: we never resolve DNS here — that would block the
    event loop and a rebinding answer could differ from the one the eventual
    connection dials. Hard egress control needs a network firewall, not a text
    deny (see ``docs/deployment.md``). Purely additive — a stray canonical form
    only *widens* what a deny can match; it never admits or blocks on its own.
    """
    t = token.strip().strip("[]")
    if not t:
        return []
    found: list[str] = []
    # Standard IPv4 / IPv6 (incl. IPv4-mapped). Strict: a bare port like "22"
    # raises here, so small integers are not mis-canonicalised.
    try:
        ip = ipaddress.ip_address(t)
        found.append(str(ip))
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            found.append(str(mapped))
    except ValueError:
        pass
    # Obfuscated IPv4 the libc resolver still accepts (inet_aton grammar:
    # decimal / octal / hex / short). Gate on an "IP-ish" shape so a bare
    # port or small count is not turned into 0.0.0.N noise.
    looks_ipish = "." in t or t.lower().startswith("0x") or (t.isdigit() and int(t) > 65535)
    if looks_ipish:
        with contextlib.suppress(OSError):
            found.append(socket.inet_ntoa(socket.inet_aton(t)))
    return list(dict.fromkeys(found))


def _with_canonical_ips(text: str, *host_tokens: str) -> str:
    """Append the canonical IP form of any of ``host_tokens`` to a probe ``text``.

    So an IP-based ``RELAY_SHELL_POLICY_DENY`` matches the address regardless of
    the encoding the caller used (SSRF-1/SSRF-2). Only forms that *differ* from
    what the caller wrote and are not already present are appended, keeping the
    probe clean for plain literals and hostnames. The caller passes the exact
    host tokens (rather than re-tokenizing ``text``) so colon-bearing literals —
    an IPv6 address, or a ``host:path`` / ``L:port:dhost:port`` phrase — are
    canonicalized as whole tokens instead of being split apart.
    """
    extra: list[str] = []
    for tok in host_tokens:
        for ip in _canonical_ips(tok):
            if ip != tok and ip not in extra and ip not in text:
                extra.append(ip)
    return f"{text} {' '.join(extra)}" if extra else text


def _augment_probe_with_ips(hosts: str) -> str:
    """Widen an ``ssh_keyscan`` host-list probe with canonical IP forms (SSRF-1).

    The host list is whitespace/comma-separated; each entry is a candidate host
    token fed to :func:`_with_canonical_ips`.
    """
    tokens = [t for t in hosts.replace(",", " ").split() if t]
    return _with_canonical_ips(hosts, *tokens)


def _forward_dhost(spec: str) -> str:
    """Best-effort destination host from an ``L:/R:`` forward spec (else "").

    ``L:lport:dhost:dport`` / ``R:rport:dhost:dport`` name a destination host
    the forward dials; ``D:lport`` (dynamic SOCKS) names none. Lenient and
    parse-free (the authoritative parse + validation happens later in
    ``SshPool.add_forward``): a malformed spec just yields no dhost, so the
    probe is only ever *widened*, never broken.
    """
    parts = spec.split(":")
    if len(parts) >= 4 and parts[0].strip().upper() in ("L", "R"):
        return parts[2]
    return ""


def _policy_text_ssh_keyscan(hosts: str) -> str:
    """The caller-chosen scan targets, so the deny list gates them (SEC-1).

    ``ssh_keyscan`` opens caller-chosen outbound TCP connections — the
    SSRF-shaped surface most worth gating by host — yet its probe text used to
    be empty, so ``RELAY_SHELL_POLICY_DENY`` never saw the targets (unlike the
    ``ssh_upload`` / ``ssh_download`` / ``ssh_forward`` synthetic builders,
    which already name their host). Returning the ``hosts`` string closes that
    gap and honours the runbook R-002 contract ("everything the executor sees,
    the policy sees"). It is also widened with the canonical form of any literal
    IP the caller wrote in an alternate encoding (SSRF-1, via
    ``_augment_probe_with_ips``) so an IP deny is not dodged by
    decimal/hex/octal/IPv4-mapped spellings. Tradeoff: the same text feeds the
    tier classifier, so a host whose name embeds a heuristic word (``reboot``,
    ``sudo``, ...) at a token start over-classifies the scan and is refused in
    ``guarded`` mode (``open`` is advisory; ``readonly`` already refuses
    Tier 1). That is a conservative false-deny with ``RELAY_SHELL_POLICY_ALLOW``
    as the escape hatch, and it matches how the transfer tools already behave.
    """
    return _augment_probe_with_ips(hosts)


class Relay:
    """Holds shared state and runs every tool through the audited path."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.audit = AuditLogger(
            settings.audit_path,
            also_stderr=settings.audit_stderr,
            fmt=settings.audit_format,
            chain=settings.audit_chain,
        )
        self.policy = Policy(settings.policy_mode, settings.policy_deny, settings.policy_allow)
        # Tier-3 confirmation broker (ADR 0009). None unless opted in, so the
        # default configuration never consults it and Relay.run stays
        # byte-identical to the pre-broker path.
        self.broker = ConfirmationBroker(settings.confirm_ttl) if settings.confirm_tier3 else None
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
        # Announce the seccomp-notify channel's status once at construction so
        # an operator who set RELAY_SHELL_SECCOMP_NOTIFY learns immediately
        # whether it actually engaged (or why it no-ops on this host).
        if settings.seccomp_notify:
            support = seccomp.platform_support()
            if support.ok:
                _log.info(
                    "seccomp-notify audit channel ON (arch=%s, kernel=%s, cap=%d)",
                    support.arch,
                    support.kernel,
                    settings.seccomp_notify_cap,
                )
            else:
                _log.warning(
                    "seccomp-notify requested but unavailable (%s); the channel is "
                    "OFF and local spawns are unaffected",
                    support.reason,
                )

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

        # Tier-3 confirmation gate (ADR 0009). Opt-in: when `self.broker` is
        # None (the default) this whole block is skipped and the path below
        # stays byte-identical. When enabled, an IRREVERSIBLE op that already
        # passed the deny list and mode check is not executed on first
        # request - the runner mints a single-use, TTL-bounded token (audited
        # as `confirm_plan`, no work() side effect) and the caller must arm it
        # via `operation_confirm` then re-issue the exact same call. A retried
        # call whose armed token is found is executed and tagged
        # `confirm_execute`. This is an added safeguard, never a bypass: the
        # deny list and mode policy have already run above.
        confirm_action = ""
        if self.broker is not None and decision.tier == Tier.IRREVERSIBLE:
            op_key = _confirm_op_key(policy_text, audit_args)
            if self.broker.consume(tool, op_key):
                confirm_action = "confirm_execute"
            else:
                challenge = self.broker.plan(tool, op_key)
                body = (
                    f"[CONFIRM REQUIRED tier {int(decision.tier)} "
                    f"({decision.tier.name}): this irreversible operation needs a second "
                    f'step. Call operation_confirm(token="{challenge.token}") then re-issue '
                    f"this exact call within {challenge.ttl}s.]"
                )
                self.audit.record(
                    tool=tool,
                    args=red,
                    output=body,
                    exit_code=None,
                    tier=int(decision.tier),
                    request_id=request_id,
                    client_id=client_id,
                    action="confirm_plan",
                )
                self.metrics.inc_tool_call(
                    tool=tool, tier=int(decision.tier), mode=mode, outcome="confirm_required"
                )
                return body

        errored = False
        # Activate the per-call seccomp-notify monitor (ADR 0006) for the
        # duration of work(). It is None unless the channel is enabled AND
        # supported; the executors consult it when they spawn a child. A
        # ContextVar keeps concurrent calls isolated and avoids threading the
        # monitor through every tool's work closure. Whoever arms the monitor
        # owns stopping it: the one-shot executor (shelltools) stops it when
        # the call's child is reaped, a PTY transport (sessions) adopts it
        # for the session's lifetime and stops it at close (B-026).
        monitor = self._seccomp_monitor(request_id)
        token = seccomp.set_active(monitor)
        try:
            body, exit_code = await work()
        except RelayError as exc:
            body, exit_code = fmt_exc(exc), None
            errored = True
        except Exception as exc:  # noqa: BLE001
            body, exit_code = fmt_exc(exc), None
            errored = True
        finally:
            seccomp.clear_active(token)

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
            action=confirm_action,
        )
        outcome = "error" if errored else "ok"
        self.metrics.inc_tool_call(tool=tool, tier=int(decision.tier), mode=mode, outcome=outcome)
        return final

    async def register_session(
        self, *, kind: str, title: str, transport: Transport, cols: int, rows: int
    ) -> Session:
        """Admit a freshly-spawned transport into the session registry.

        The shared registration path for ``shell_spawn`` / ``ssh_spawn``
        (runbook R-003). If the registry refuses — typically the session
        limit — the transport is closed before the error propagates, so the
        already-spawned child is reaped instead of leaking unsupervised.
        ``aclose()`` also releases the per-session seccomp monitor when one
        is attached (B-026).
        """
        try:
            return await self.sessions.add(
                kind=kind, title=title, transport=transport, cols=cols, rows=rows
            )
        except BaseException:
            with contextlib.suppress(Exception):
                await transport.aclose()
            raise

    def connect_kwargs(
        self,
        user: str,
        port: int,
        key_path: str,
        known_hosts: str,
        jump: str,
        connect_timeout: int = 0,
    ) -> dict[str, Any]:
        """Build the dict that ``SshPool.connect`` accepts as ``**kwargs``.

        ``connect_timeout`` is an optional overlay for tools like
        ``ssh_check`` and ``ssh_fanout`` that probe many hosts at once
        and want a tighter per-host bound than ``settings.ssh_connect_timeout``.
        A zero overlay means "fall back to the server-wide default" —
        the same semantics ``SshPool.connect`` already implements, so
        callers do not have to special-case it.
        """
        ck: dict[str, Any] = {
            "user": user,
            "port": port,
            "key_path": key_path,
            "known_hosts": known_hosts,
            "jump": jump,
        }
        if connect_timeout > 0:
            ck["connect_timeout"] = connect_timeout
        return ck

    def _seccomp_monitor(self, request_id: str) -> seccomp.SeccompMonitor | None:
        """Build a per-call seccomp-notify monitor, or ``None`` if disabled.

        ``None`` whenever the channel is off (the default) or the host lacks
        the prerequisites (Linux/x86_64/kernel 5.5+/CAP_SYS_ADMIN), so the
        spawn path stays byte-identical. When active, every observed syscall
        is routed to the audit log (an additive ``syscall_notify`` line tied
        to this ``request_id``) and the bounded ``/metrics`` counters. For a
        PTY spawn the monitor outlives the call — the session transport
        adopts it (B-026) — so its events keep carrying the *spawning*
        call's ``request_id`` for the life of the session.
        """
        if not self.settings.seccomp_notify:
            return None
        support = seccomp.platform_support()
        if not support.ok:
            return None

        def _on_event(evt: seccomp.SyscallEvent) -> None:
            self.audit.record_syscall(
                pid=evt.pid,
                syscall=evt.syscall,
                nr=evt.nr,
                args=evt.args,
                request_id=request_id,
            )
            self.metrics.inc_seccomp_event(syscall=evt.syscall)

        def _on_overflow(pid: int) -> None:
            self.audit.record_syscall_overflow(
                pid=pid, cap=self.settings.seccomp_notify_cap, request_id=request_id
            )
            self.metrics.inc_seccomp_overflow()

        return seccomp.SeccompMonitor(
            cap=self.settings.seccomp_notify_cap,
            arch=support.arch,
            on_event=_on_event,
            on_overflow=_on_overflow,
        )


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
        """Run one non-interactive shell command on the local host; returns its combined output.

        Use for a command that runs and exits on its own. For an interactive
        or long-lived program that needs a TTY (a REPL, a pager, a prompt) use
        ``shell_spawn``; for several statements or a non-bash interpreter use
        ``shell_script``.

        Timeout and output size are clamped to the server limits. Set
        ``use_shell=false`` to exec an argv without a shell.
        """
        t = app.clamp_timeout(timeout)
        policy_text = _policy_text_shell_exec(command, stdin, env_json)
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
        """Run a multi-line script (bash/sh/python) fed on stdin; returns its output.

        Use when you have several statements or need a non-bash interpreter.
        For a single command use ``shell_exec``; for interactive or long-lived
        work that needs a TTY use ``shell_spawn``.

        With ``strict`` and a shell interpreter, ``set -euo pipefail`` is
        prepended so failures abort early.
        """
        t = app.clamp_timeout(timeout)
        policy_text = _policy_text_shell_script(script, env_json)
        return await app.run(
            tool="shell_script",
            ctx=ctx,
            audit_args={
                "interpreter": interpreter,
                "strict": strict,
                "script": script,
                "timeout": t,
                "cwd": cwd,
                "env_json": env_json,
            },
            policy_text=policy_text,
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

        Use when the work is interactive or long-lived and needs a real TTY: a
        REPL or TUI, a program that prompts (including a sudo password), or a
        job you start and watch. Drive the returned id with ``session_send`` /
        ``session_recv`` (``session_resize`` / ``session_kill`` /
        ``session_list`` to manage it) - spawning and the session tools are one
        workflow, not alternatives. For a one-shot command that just runs and
        exits, use ``shell_exec`` instead.
        """

        async def _work() -> tuple[str, int | None]:
            argv = spawn_argv(command)
            transport = await LocalPtyTransport.spawn(
                argv, cwd=cwd or None, env=build_env(env_json), cols=cols, rows=rows
            )
            sess = await app.register_session(
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

        policy_text = _policy_text_shell_spawn(command, env_json)
        return await app.run(
            tool="shell_spawn",
            ctx=ctx,
            audit_args={
                "command": command or "/bin/bash",
                "size": f"{cols}x{rows}",
                "cwd": cwd,
                "env_json": env_json,
            },
            policy_text=policy_text,
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
        """Run one non-interactive command on a remote host over SSH; returns its output.

        Use for a remote command that runs and exits on its own. For an
        interactive or long-lived remote program that needs a TTY use
        ``ssh_spawn``; to run one command across many hosts at once use
        ``ssh_fanout``.

        ``host`` may be an inventory/ssh_config alias or ``user@host``.
        ``known_hosts`` is ``strict`` | ``accept-new`` | ``ignore``.
        """
        t = app.clamp_timeout(timeout)
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)
        return await app.run(
            tool="ssh_exec",
            ctx=ctx,
            audit_args={
                "host": host,
                "command": command,
                "timeout": t,
                "user": user,
                "port": port,
                "key_path": key_path,
                "jump": jump,
                "known_hosts": known_hosts or app.settings.ssh_known_hosts,
            },
            policy_text=_policy_text_ssh_exec(host, command),
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
        """Open a persistent interactive PTY on a remote host; returns a session id.

        Use when the remote work is interactive or long-lived and needs a real
        TTY (a remote shell, a REPL, a program that prompts). Drive the returned
        id with ``session_send`` / ``session_recv``, exactly like a local
        ``shell_spawn`` session. For a one-shot remote command, use ``ssh_exec``
        instead.
        """
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)

        async def _work() -> tuple[str, int | None]:
            transport = await app.ssh.open_process(
                host, command=command, cols=cols, rows=rows, connect_kwargs=ck
            )
            sess = await app.register_session(
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
            audit_args={
                "host": host,
                "command": command or "shell",
                "size": f"{cols}x{rows}",
                "user": user,
                "port": port,
                "key_path": key_path,
                "known_hosts": known_hosts or app.settings.ssh_known_hosts,
            },
            policy_text=_policy_text_ssh_spawn(host, command),
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
            policy_text=_policy_text_session_send(data),
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
        timeout: int = 0,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Upload a file or tree to a remote host via SFTP.

        ``timeout`` caps the transfer in seconds (clamped to the server max);
        ``0`` (default) means no per-call cap, leaving only the connection
        keepalive. A transfer that exceeds the cap returns a
        ``[TIMEOUT after Ns]`` string.
        """
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)
        t = app.clamp_timeout(timeout) if timeout > 0 else 0

        async def _work() -> tuple[str, int | None]:
            msg = await app.ssh.sftp_put(
                host, local_path, remote_path, recurse=recursive, connect_kwargs=ck, timeout=t
            )
            return (msg, None)

        return await app.run(
            tool="ssh_upload",
            ctx=ctx,
            audit_args={
                "host": host,
                "local": local_path,
                "remote": remote_path,
                "timeout": t,
                "known_hosts": known_hosts or app.settings.ssh_known_hosts,
            },
            policy_text=_policy_text_ssh_upload(host, local_path, remote_path),
            max_output=2048,
            work=_work,
        )

    @mcp.tool()
    async def ssh_download(
        host: str,
        remote_path: str,
        local_path: str,
        recursive: bool = False,
        timeout: int = 0,
        user: str = "",
        port: int = 0,
        key_path: str = "",
        known_hosts: str = "",
        jump: str = "",
        ctx: Context | None = None,
    ) -> str:
        """Download a file or tree from a remote host via SFTP.

        ``timeout`` caps the transfer in seconds (clamped to the server max);
        ``0`` (default) means no per-call cap, leaving only the connection
        keepalive. A transfer that exceeds the cap returns a
        ``[TIMEOUT after Ns]`` string.
        """
        ck = app.connect_kwargs(user, port, key_path, known_hosts, jump)
        t = app.clamp_timeout(timeout) if timeout > 0 else 0

        async def _work() -> tuple[str, int | None]:
            msg = await app.ssh.sftp_get(
                host, remote_path, local_path, recurse=recursive, connect_kwargs=ck, timeout=t
            )
            return (msg, None)

        return await app.run(
            tool="ssh_download",
            ctx=ctx,
            audit_args={
                "host": host,
                "remote": remote_path,
                "local": local_path,
                "timeout": t,
                "known_hosts": known_hosts or app.settings.ssh_known_hosts,
            },
            policy_text=_policy_text_ssh_download(host, remote_path, local_path),
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
            audit_args={
                "host": host,
                "spec": spec,
                "known_hosts": known_hosts or app.settings.ssh_known_hosts,
            },
            policy_text=_policy_text_ssh_forward(spec),
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
            if len(names) > _SSH_CHECK_MAX_HOSTS:
                return (
                    f"[ERROR: {len(names)} hosts exceeds the per-call cap of "
                    f"{_SSH_CHECK_MAX_HOSTS}; split into smaller batches]",
                    None,
                )
            tmo = clamp(timeout, 1, 60)
            ck = app.connect_kwargs("", 0, "", "", "", connect_timeout=tmo)
            sem = asyncio.Semaphore(_SSH_CHECK_CONCURRENCY)

            async def _probe(name: str) -> str:
                async with sem:
                    try:
                        out, code = await app.ssh.run(
                            name, "echo ok", timeout=tmo, connect_kwargs=ck
                        )
                        ok = code == 0 and "ok" in out
                        return f"{name}: {'ok' if ok else 'UNREACHABLE'}"
                    except Exception as exc:  # noqa: BLE001
                        return f"{name}: UNREACHABLE ({exc.__class__.__name__})"

            # gather preserves input order in the result list regardless of
            # which probe finishes first.
            lines = await asyncio.gather(*(_probe(n) for n in names))
            return ("\n".join(lines), None)

        return await app.run(
            tool="ssh_check",
            ctx=ctx,
            audit_args={"hosts": hosts or "inventory"},
            policy_text=_policy_text_ssh_check(hosts),
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
        # Constructed once, outside _work, so app.run() sees it before
        # admitting; the tier heuristics fire identically to ssh_exec, and the
        # target hosts reach the deny list (F2).
        policy_text = _policy_text_ssh_fanout(hosts, command)

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

            ck = app.connect_kwargs("", 0, "", "", "", connect_timeout=tmo)

            async def _run_one(name: str) -> dict[str, Any]:
                async with sem:
                    try:
                        out, code = await app.ssh.run(
                            name,
                            command,
                            timeout=tmo,
                            connect_kwargs=ck,
                            max_output_bytes=per_host_budget,
                        )
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
            # The scan targets are the caller-controlled, executor-visible part,
            # so the deny list must see them (SEC-1). See _policy_text_ssh_keyscan.
            policy_text=_policy_text_ssh_keyscan(hosts),
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
            _seccomp_support = seccomp.platform_support()
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
                    "max_forwards": cfg.max_forwards,
                },
                "audit": {
                    "path": app.audit.path,
                    "degraded": app.audit.degraded,
                    "format": app.audit.format,
                    "chain": app.audit.chain,
                },
                "confirm": {
                    "tier3": cfg.confirm_tier3,
                    "ttl": cfg.confirm_ttl,
                    "pending": app.broker.pending() if app.broker is not None else 0,
                },
                "seccomp": {
                    "notify": cfg.seccomp_notify,
                    "supported": _seccomp_support.ok,
                    "reason": _seccomp_support.reason,
                    "cap": cfg.seccomp_notify_cap,
                    "filter_version": seccomp.SECCOMP_FILTER_VERSION,
                },
                "ssh": {
                    "known_hosts_default": cfg.ssh_known_hosts,
                    "inventory_hosts": len(app.inventory.hosts()),
                    "ssh_config": app.inventory.ssh_config_file,
                    "connect_timeout": cfg.ssh_connect_timeout,
                    "keepalive": cfg.ssh_keepalive,
                    "idle_timeout": cfg.ssh_idle_timeout,
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
    async def operation_confirm(token: str, ctx: Context | None = None) -> str:
        """Arm a Tier-3 confirmation token, then re-issue the original call.

        Second step of the opt-in confirmation flow (ADR 0009). When the
        confirmation broker is enabled (``RELAY_SHELL_CONFIRM_TIER3``), an
        irreversible (Tier 3) call first returns a token instead of running;
        pass that token here to arm it, then re-issue the *exact* same call to
        execute it. Tokens are single-use and expire after
        ``RELAY_SHELL_CONFIRM_TTL`` seconds. When the broker is disabled this
        reports that and changes nothing.
        """

        async def _work() -> tuple[str, int | None]:
            if app.broker is None:
                return (
                    "[confirmation broker disabled (RELAY_SHELL_CONFIRM_TIER3 is off)]",
                    None,
                )
            if app.broker.arm(token):
                return ("[armed: re-issue the exact Tier-3 call now to execute it]", None)
            return ("[invalid or expired confirmation token]", None)

        # Audit the arm attempt, but never log the raw capability token: a
        # non-replayable fingerprint is enough to correlate with the plan
        # record without putting a live token in the audit trail.
        fingerprint = sha256_hex(token)[:12] if token else ""
        return await app.run(
            tool="operation_confirm",
            ctx=ctx,
            audit_args={"token_sha256": fingerprint},
            policy_text="",
            max_output=1024,
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
    #
    # Resource reads ALSO bypass `Policy.check`: `RELAY_SHELL_POLICY_DENY`
    # and `RELAY_SHELL_POLICY_MODE=readonly|guarded` do NOT apply to
    # resource URIs. This is deliberate — the data exposed here is the same
    # `ssh_hosts` / `ssh_config_file` metadata a Tier-0 tool already returns
    # in any mode, so admission-controlling resources separately would be
    # defense without depth. Documented in SECURITY.md §Scope. If a
    # deployment ever needs to refuse a specific resource, route it through
    # `Relay.run` with a `policy_text` that names the resource.
    #
    # The audit `tool` field is kept STABLE per resource (no user-controlled
    # data interpolated): the host parameter for the templated resource is
    # carried in `args` instead, so `redact_args` can scrub embedded secrets
    # and tool-name cardinality stays bounded for downstream audit consumers.

    def _audit_resource_read(name: str, body: str, args: dict[str, Any] | None = None) -> None:
        tool_label = f"resource:{name}"
        app.audit.record(
            tool=tool_label,
            args=redact_args(args or {}),
            output=body,
            exit_code=None,
            tier=0,
        )
        # Tick the same counter tool calls use, with the same
        # tool/tier/mode/outcome label set, so a flood of resource reads
        # is visible on /metrics instead of being audit-only. Cardinality
        # is bounded by the three registered resource names
        # (resource:inventory, resource:inventory_host, resource:ssh-config).
        app.metrics.inc_tool_call(
            tool=tool_label,
            tier=0,
            mode=app.settings.policy_mode,
            outcome="ok",
        )

    # Bound every resource payload to the same cap tools observe via
    # `Relay.run`. Without this, a huge inventory would produce arbitrarily
    # large payloads (and audit-hashing work) in a single read.
    _resource_cap = app.clamp_output(cfg.max_output)

    @mcp.resource(
        "relay-shell://inventory",
        name="inventory",
        title="Host inventory",
        description=(
            "Flat list of all hosts resolved from ~/.ssh/config and the optional "
            "RELAY_SHELL_INVENTORY file, as a JSON array of host specs. Same "
            "data shape as the ssh_hosts tool. Bodies are bounded by the same "
            "max_output cap as tools; oversized responses get a [TRUNCATED ...] "
            "marker appended, the same way tools do."
        ),
        mime_type="application/json",
    )
    def _resource_inventory() -> str:
        body = json.dumps([h.as_dict() for h in app.inventory.hosts()], default=str)
        body = truncate(body, _resource_cap)
        _audit_resource_read("inventory", body)
        return body

    @mcp.resource(
        "relay-shell://inventory/{host}",
        name="inventory_host",
        title="Single host spec",
        description=(
            "Resolved spec for one inventory entry (or a passthrough spec the "
            "ssh layer would accept) as JSON. Audit records this read as "
            'tool="resource:inventory_host" with the host in args (so redaction '
            "runs and the tool-name cardinality stays bounded)."
        ),
        mime_type="application/json",
    )
    def _resource_inventory_host(host: str) -> str:
        spec = app.inventory.resolve(host).as_dict()
        body = json.dumps(spec, default=str)
        body = truncate(body, _resource_cap)
        _audit_resource_read("inventory_host", body, args={"host": host})
        return body

    @mcp.resource(
        "relay-shell://ssh-config",
        name="ssh_config",
        title="SSH config metadata",
        description=(
            "Path to the active ssh_config and the sorted list of non-wildcard "
            "Host aliases declared in it, as JSON. Inventory overrides do not "
            "suppress aliases - any name the active ssh_config declares appears "
            "here, so a client gets an accurate view of what the file contains."
        ),
        mime_type="application/json",
    )
    def _resource_ssh_config() -> str:
        payload = {
            "path": app.inventory.ssh_config_file,
            "aliases": app.inventory.ssh_config_aliases(),
        }
        body = json.dumps(payload, default=str)
        body = truncate(body, _resource_cap)
        _audit_resource_read("ssh-config", body)
        return body

    # --- MCP prompts --------------------------------------------------------
    #
    # A prompt is reusable, client-pullable guidance - the protocol-native home
    # for *detailed* "when to use which tool" instructions (the FastMCP
    # `instructions` string carries the concise version surfaced at initialize).
    # Like a resource read, a prompt fetch does NOT flow through `Relay.run`:
    # there is no work to admit, time out, or truncate. But a fetch IS a
    # model-context pull, so it is audited (tier 0, tool="prompt:<name>") to
    # preserve the invariant that every context the model pulls in is visible
    # to the operator. The body is bounded by the same `max_output` cap
    # resources observe. See ADR 0008.
    #
    # `list_prompts` returns metadata only and never calls the function, so the
    # audit fires on `prompts/get` (a real fetch), not on discovery - mirroring
    # how resource reads are audited on read, not on listing.

    def _audit_prompt_read(name: str, body: str) -> None:
        tool_label = f"prompt:{name}"
        # No user-controlled arguments enter this prompt, so args is empty and
        # the tool label is a stable constant (cardinality stays bounded for
        # audit/metrics consumers, same contract as the resource reads above).
        app.audit.record(
            tool=tool_label,
            args={},
            output=body,
            exit_code=None,
            tier=0,
        )
        app.metrics.inc_tool_call(
            tool=tool_label,
            tier=0,
            mode=app.settings.policy_mode,
            outcome="ok",
        )

    @mcp.prompt(
        name="operating_guide",
        title="relay-shell operating guide",
        description=(
            "How to drive relay-shell: choosing between a one-shot command and "
            "a persistent PTY session, the spawn+session workflow, the fleet "
            "and file-transfer entry points, and the bounded, audited execution "
            "model to expect. Pull this when deciding which tool to use."
        ),
    )
    def _prompt_operating_guide() -> str:
        body = truncate(_OPERATING_GUIDE, _resource_cap)
        _audit_prompt_read("operating_guide", body)
        return body

    # Expose the constructed Relay so `__main__` can wire graceful shutdown
    # (sessions + ssh pool teardown) and `--check-config` can read the audit
    # degraded flag without constructing a second Relay (which would open
    # the audit log twice and double-load the inventory). The attribute is
    # private-flavored but stable enough to depend on within the package.
    mcp.relay = app  # type: ignore[attr-defined]
    return mcp


_INSTRUCTIONS = """\
relay-shell - shell and SSH operations.

Choosing a tool:
- A command that runs and exits on its own -> shell_exec (local) or
  ssh_exec (remote). Several statements or a non-bash interpreter ->
  shell_script.
- Interactive or long-lived work that needs a real TTY (a REPL, a TUI, a
  pager, a password prompt, a job you watch) -> shell_spawn (local) or
  ssh_spawn (remote). These return a session id; drive it with session_send
  and session_recv, and manage it with session_resize, session_kill, and
  session_list. Spawning and the session tools are one workflow, not
  alternatives: the spawn creates the PTY, the session tools drive it.
- Move files with ssh_upload / ssh_download; tunnel ports with ssh_forward
  (inspect and close via ssh_forward_list / ssh_forward_close).
- Before fleet work, list hosts with ssh_hosts and probe them with
  ssh_check; run one command across many hosts with ssh_fanout; seed
  known_hosts with ssh_keyscan.

Diagnostics: server_info reports limits and policy mode; audit_tail returns
the last N audit records.

Every call is tier-classified, bounded (timeout + output caps), and appended
to an append-only audit log (output is hashed, never stored). When the
optional Tier-3 confirmation broker is enabled, an irreversible command
returns a token first; arm it with operation_confirm and re-issue the same
call to execute it.
"""


# Detailed operating guide served by the `operating_guide` MCP prompt. The
# `_INSTRUCTIONS` string above is the concise version handed to every client at
# initialize; this is the longer, client-pullable form (ADR 0008).
_OPERATING_GUIDE = """\
relay-shell operating guide
===========================

relay-shell exposes local shell and SSH operations as MCP tools. Every call is
classified into a tier, bounded by a timeout and an output cap, and appended to
an append-only audit log (the output body is hashed, never stored). Tools never
raise into the transport; failures come back as bounded strings.

Choosing a tool
---------------
- A command that runs and exits on its own -> shell_exec (local) or
  ssh_exec (remote). This is the one-shot, non-interactive path.
- Several statements, or a non-bash interpreter (sh/python) -> shell_script.
- Interactive or long-lived work that needs a real TTY - a REPL or TUI, a
  pager, a program that prompts (including a sudo password), or a job you
  start and watch -> shell_spawn (local) or ssh_spawn (remote). These return a
  session id.
- One command across many hosts at once -> ssh_fanout.

Spawn and sessions are one workflow, not alternatives
-----------------------------------------------------
shell_spawn / ssh_spawn create a PTY and return a session id; the session
tools then drive that id:
  session_send   - send input (enter=true appends a newline)
  session_recv   - read new/buffered output, waiting up to timeout
  session_resize - resize the PTY (cols x rows)
  session_kill   - signal and (default) reap the session
  session_list   - list active sessions with size/age/idle counters
A typical loop:
  id = shell_spawn(command="/bin/bash")
  session_send(id, "kubectl get pods")
  session_recv(id, timeout=3)
  session_kill(id)

Working with a fleet
--------------------
- ssh_hosts    list the resolved inventory (~/.ssh/config + the optional
               inventory file).
- ssh_check    probe connectivity (whole inventory, or a host list).
- ssh_fanout   run one command across many hosts; per-host exit codes in one
               JSON object.
- ssh_keyscan  fetch host public keys to pre-populate known_hosts so a service
               account can run the strict known-hosts mode unattended.
A host is an inventory/ssh_config alias or user@host. known_hosts is
strict | accept-new | ignore.

Moving data and ports
---------------------
- ssh_upload / ssh_download   SFTP transfer (recursive supported).
- ssh_forward                 local (L), remote (R), or dynamic SOCKS (D)
                              forward; ssh_forward_list / ssh_forward_close
                              inspect and close active forwards.

Diagnostics
-----------
- server_info  version, effective limits, policy mode, audit path and state.
- audit_tail   the last N audit records (read-only).

Confirming an irreversible operation (opt-in)
---------------------------------------------
When the deployment enables the Tier-3 confirmation broker
(RELAY_SHELL_CONFIRM_TIER3), an irreversible command (e.g. rm -rf, mkfs)
does not run on first request: it returns [CONFIRM REQUIRED tier 3 ... token="..."].
Call operation_confirm(token="...") to arm it, then re-issue the exact same
call to execute it. Tokens are single-use and expire. When the broker is off
(the default) this never triggers.

What a result can look like
---------------------------
- [exit N] followed by output             a command that completed.
- [DENIED tier N (NAME): reason]          refused by policy (depends on
                                          RELAY_SHELL_POLICY_MODE and the
                                          deny/allow lists).
- [TIMEOUT after Ns]                      exceeded the clamped timeout.
- [ERROR: ExcType: message]               any other failure, contained.
- [TRUNCATED - N bytes total, M shown]    output exceeded the budget.
"""
