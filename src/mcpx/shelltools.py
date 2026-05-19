"""Local command and script execution.

Pure execution helpers returning ``(body, exit_code)``. They never raise for
ordinary failures (timeouts, bad cwd, decode issues) - the server wrapper adds
the ``[exit N]`` prefix, truncation, policy, and audit. Long-lived interactive
PTYs are handled by :mod:`mcpx.sessions`; this module covers one-shot runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shlex
import signal
import sys

from .errors import fmt_exc

__all__ = ["build_env", "run_command", "run_script", "spawn_argv"]


def build_env(overlay_json: str = "") -> dict[str, str]:
    """Inherited environment plus deterministic defaults and an optional overlay."""
    env = dict(os.environ)
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env["LANG"] = env.get("LANG", "C.UTF-8")
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["GIT_TERMINAL_PROMPT"] = "0"
    if overlay_json.strip():
        try:
            extra = json.loads(overlay_json)
            if isinstance(extra, dict):
                for key, val in extra.items():
                    env[str(key)] = str(val)
        except json.JSONDecodeError:
            pass
    return env


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError, OSError):
        proc.kill()


async def _drive(
    proc: asyncio.subprocess.Process,
    stdin_data: bytes | None,
    timeout: int,
    merge_stderr: bool,
) -> tuple[str, int | None]:
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin_data), timeout)
    except TimeoutError:
        _kill_tree(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), 3)
        return (f"[TIMEOUT after {timeout}s]", None)
    text = out.decode("utf-8", "replace")
    if not merge_stderr and err:
        text += err.decode("utf-8", "replace")
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
) -> tuple[str, int | None]:
    """Run a single command and return ``(combined_output, exit_code)``."""
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
    try:
        if use_shell:
            proc = await asyncio.create_subprocess_shell(command, **common)  # type: ignore[arg-type]
        else:
            argv = shlex.split(command)
            if not argv:
                return ("[ERROR: empty command]", None)
            proc = await asyncio.create_subprocess_exec(*argv, **common)  # type: ignore[arg-type]
    except (OSError, ValueError) as exc:
        return (fmt_exc(exc), None)
    return await _drive(proc, stdin_data, timeout, merge_stderr)


async def run_script(
    script: str,
    *,
    interpreter: str = "bash",
    strict: bool = True,
    timeout: int,
    cwd: str = "",
    env_json: str = "",
) -> tuple[str, int | None]:
    """Run a multi-line script via the chosen interpreter (fed on stdin)."""
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
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd or None,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        return (fmt_exc(exc), None)
    return await _drive(proc, body.encode("utf-8"), timeout, merge_stderr=True)


def spawn_argv(command: str) -> list[str]:
    """Resolve the argv for an interactive local PTY session."""
    if not command.strip():
        return ["/bin/bash"]
    return shlex.split(command)
