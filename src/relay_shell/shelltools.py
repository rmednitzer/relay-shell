"""Local command and script execution.

Pure execution helpers returning ``(body, exit_code)``. They never raise for
ordinary failures (timeouts, bad cwd, decode issues) - the server wrapper adds
the ``[exit N]`` prefix, truncation, policy, and audit. Long-lived interactive
PTYs are handled by :mod:`relay_shell.sessions`; this module covers one-shot runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shlex
import signal
import sys

from . import seccomp
from .errors import fmt_exc

__all__ = ["build_env", "run_command", "run_script", "spawn_argv"]


def build_env(overlay_json: str = "") -> dict[str, str]:
    """Inherited environment plus deterministic defaults and an optional overlay.

    ``overlay_json`` may be empty or a JSON object. Keys map to string values;
    a ``null`` value removes the variable from the environment. Non-object JSON
    and malformed input are ignored - tools must not crash on a bad overlay.
    """
    env = dict(os.environ)
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env.setdefault("LANG", "C.UTF-8")
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["GIT_TERMINAL_PROMPT"] = "0"
    if not overlay_json.strip():
        return env
    try:
        extra = json.loads(overlay_json)
    except json.JSONDecodeError:
        return env
    if not isinstance(extra, dict):
        return env
    for key, val in extra.items():
        name = str(key)
        if val is None:
            env.pop(name, None)
        else:
            env[name] = str(val)
    return env


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError, OSError):
        proc.kill()


async def _feed_stdin(proc: asyncio.subprocess.Process, data: bytes | None) -> None:
    """Write ``data`` to the child's stdin and close it, concurrently with the
    output drain (so a large stdin cannot deadlock against a full stdout pipe).
    Best-effort: a child that exits early / closes its stdin is not an error."""
    stdin = proc.stdin
    if stdin is None:
        return
    try:
        if data:
            stdin.write(data)
            await stdin.drain()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        with contextlib.suppress(Exception):
            stdin.close()


async def _drain_capped(
    stream: asyncio.StreamReader, parts: list[bytes], kept: list[int], cap: int | None
) -> int:
    """Read ``stream`` to EOF, keeping at most ``cap`` bytes across all streams
    sharing ``kept`` and discarding the rest. Returns the true bytes seen.

    Draining to EOF (rather than stopping at the cap) lets the child run to
    completion so its exit code and the true output length survive, while relay
    memory stays bounded — the same discipline ``SshPool.run`` uses for the
    remote path. ``cap is None`` keeps everything (the historical behaviour)."""
    seen = 0
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return seen
        seen += len(chunk)
        if cap is None:
            parts.append(chunk)
        else:
            budget = cap - kept[0]
            if budget > 0:
                piece = chunk[:budget]
                parts.append(piece)
                kept[0] += len(piece)


async def _drive(
    proc: asyncio.subprocess.Process,
    stdin_data: bytes | None,
    timeout: int,
    merge_stderr: bool,
    output_cap: int | None = None,
) -> tuple[str, int | None]:
    # PERF-4: bound the buffered output to ``output_cap`` (the server passes
    # ``max_output_hard``, the absolute ceiling) instead of accumulating the full
    # child output in relay memory via ``communicate()`` and truncating only
    # afterward. A single high-volume producer (`cat /dev/zero`, a runaway build
    # log) could otherwise grow the long-lived relay process without limit — a
    # memory DoS reachable by a Tier-1 command that even ``guarded`` mode permits.
    # The returned bytes are byte-identical (the server truncates to
    # ``clamp_output(max_output) <= output_cap`` regardless); only relay memory
    # changes. ``output_cap is None`` preserves the historical unbounded path.
    cap = output_cap if (output_cap is not None and output_cap > 0) else None
    out_parts: list[bytes] = []
    err_parts: list[bytes] = []
    # One shared budget across stdout+stderr so combined buffered bytes stay
    # within ``cap`` (matching the fix applied to SshPool.run).
    kept = [0]

    async def _collect() -> int:
        readers = [_drain_capped(proc.stdout, out_parts, kept, cap)]  # type: ignore[arg-type]
        if not merge_stderr and proc.stderr is not None:
            readers.append(_drain_capped(proc.stderr, err_parts, kept, cap))
        # Feed stdin and drain output in one gather so a wait_for timeout cancels
        # every child task together (no detached stdin writer left running).
        results = await asyncio.gather(_feed_stdin(proc, stdin_data), *readers)
        await proc.wait()
        return sum(r for r in results[1:] if isinstance(r, int))

    try:
        await asyncio.wait_for(_collect(), timeout)
    except TimeoutError:
        _kill_tree(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), 3)
        return (f"[TIMEOUT after {timeout}s]", None)
    text = b"".join(out_parts).decode("utf-8", "replace")
    if not merge_stderr and err_parts:
        text += b"".join(err_parts).decode("utf-8", "replace")
    return (text, proc.returncode)


async def run_command(
    command: str,
    *,
    timeout: int,
    cwd: str = "",
    stdin: str = "",
    merge_stderr: bool = True,
    use_shell: bool = True,
    env_json: str = "",
    output_cap: int | None = None,
) -> tuple[str, int | None]:
    """Run a single command and return ``(combined_output, exit_code)``.

    ``output_cap`` bounds the bytes buffered in relay memory (the server passes
    ``max_output_hard``); the child still runs to completion and the returned
    output is byte-identical after the caller's own truncation (PERF-4)."""
    env = build_env(env_json)
    stdin_data = stdin.encode("utf-8") if stdin else None
    stderr_dst = asyncio.subprocess.STDOUT if merge_stderr else asyncio.subprocess.PIPE
    common = {
        "cwd": cwd or None,
        "env": env,
        "stdin": asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
        "stdout": asyncio.subprocess.PIPE,
        "stderr": stderr_dst,
        "start_new_session": True,
    }
    argv: list[str] = []
    if not use_shell:
        argv = shlex.split(command)
        if not argv:
            return ("[ERROR: empty command]", None)
    # Optional, opt-in seccomp-notify audit channel (ADR 0006). `extras` is
    # {} unless the active monitor armed (CAP_SYS_ADMIN + enabled), keeping
    # the default spawn byte-identical. arm() must precede the spawn; stop()
    # tears the supervisor down once the child is reaped.
    monitor = seccomp.get_active()
    extras = monitor.arm() if monitor is not None else {}
    try:
        try:
            if use_shell:
                proc = await asyncio.create_subprocess_shell(command, **common, **extras)  # type: ignore[arg-type]
            else:
                proc = await asyncio.create_subprocess_exec(*argv, **common, **extras)  # type: ignore[arg-type, misc]
        except (OSError, ValueError) as exc:
            return (fmt_exc(exc), None)
        return await _drive(proc, stdin_data, timeout, merge_stderr, output_cap)
    finally:
        if monitor is not None:
            monitor.stop()


async def run_script(
    script: str,
    *,
    interpreter: str = "bash",
    strict: bool = True,
    timeout: int,
    cwd: str = "",
    env_json: str = "",
    output_cap: int | None = None,
) -> tuple[str, int | None]:
    """Run a multi-line script via the chosen interpreter (fed on stdin).

    ``output_cap`` bounds the bytes buffered in relay memory (PERF-4), like
    :func:`run_command`."""
    interp = interpreter.strip().lower()
    if interp in {"bash", "sh"}:
        binary = "/bin/bash" if interp == "bash" else "/bin/sh"
        argv = [binary, "-s"]
        body = script
        if strict:
            body = "set -euo pipefail\n" + script
    elif interp in {"python", "python3", "py"}:
        argv = [sys.executable or "python3", "-"]
        body = script
    else:
        return (f"[ERROR: unsupported interpreter: {interpreter}]", None)

    env = build_env(env_json)
    monitor = seccomp.get_active()
    extras = monitor.arm() if monitor is not None else {}
    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd or None,
                env=env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
                **extras,  # type: ignore[arg-type]
            )
        except (OSError, ValueError) as exc:
            return (fmt_exc(exc), None)
        return await _drive(
            proc, body.encode("utf-8"), timeout, merge_stderr=True, output_cap=output_cap
        )
    finally:
        if monitor is not None:
            monitor.stop()


def spawn_argv(command: str) -> list[str]:
    """Resolve the argv for an interactive local PTY session."""
    if not command.strip():
        return ["/bin/bash"]
    return shlex.split(command)
