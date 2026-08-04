from __future__ import annotations

from relay_shell.shelltools import build_env, run_command, run_script, spawn_argv


async def test_run_command_echo() -> None:
    out, code = await run_command("echo hello-world", timeout=5)
    assert code == 0
    assert "hello-world" in out


async def test_run_command_nonzero() -> None:
    _out, code = await run_command("exit 7", timeout=5)
    assert code == 7


async def test_run_command_timeout() -> None:
    out, code = await run_command("sleep 5", timeout=1)
    assert code is None
    assert "TIMEOUT" in out


async def test_run_command_stdin_and_no_shell() -> None:
    out, code = await run_command("cat", timeout=5, stdin="piped-in\n")
    assert code == 0 and "piped-in" in out
    out2, code2 = await run_command("/bin/echo argv-mode", timeout=5, use_shell=False)
    assert code2 == 0 and "argv-mode" in out2


async def test_run_command_env_overlay() -> None:
    out, code = await run_command("echo $OVL_VAR", timeout=5, env_json='{"OVL_VAR": "zzz"}')
    assert code == 0 and "zzz" in out


async def test_run_script_bash_strict_aborts() -> None:
    out, code = await run_script(
        "false\necho SHOULD_NOT_PRINT", interpreter="bash", strict=True, timeout=5
    )
    assert code != 0
    assert "SHOULD_NOT_PRINT" not in out


async def test_run_script_python() -> None:
    out, code = await run_script("print('from-python')", interpreter="python", timeout=5)
    assert code == 0 and "from-python" in out


async def test_run_script_bad_interpreter() -> None:
    out, code = await run_script("noop", interpreter="malbolge", timeout=5)
    assert code is None and "unsupported interpreter" in out


def test_build_env_defaults() -> None:
    env = build_env()
    assert env["DEBIAN_FRONTEND"] == "noninteractive"
    assert "PATH" in env


def test_build_env_overlay_removes_with_null() -> None:
    env = build_env('{"GIT_TERMINAL_PROMPT": null, "MY_VAR": "ok"}')
    assert "GIT_TERMINAL_PROMPT" not in env
    assert env["MY_VAR"] == "ok"


def test_build_env_ignores_non_object_overlay() -> None:
    # Arrays, primitives, and malformed JSON are dropped without raising; the
    # deterministic defaults (DEBIAN_FRONTEND, GIT_TERMINAL_PROMPT, ...) still
    # apply on top of the inherited environment.
    for overlay in ("[1, 2]", "true", "42", "not json"):
        env = build_env(overlay)
        assert env["DEBIAN_FRONTEND"] == "noninteractive"
        assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_build_env_overlay_coerces_values_to_strings() -> None:
    env = build_env('{"PORT": 8080, "FLAG": true}')
    assert env["PORT"] == "8080"
    assert env["FLAG"] == "True"


def test_spawn_argv() -> None:
    assert spawn_argv("") == ["/bin/bash"]
    assert spawn_argv("python3 -i") == ["python3", "-i"]


# --- PERF-4: bounded output buffering (memory cap on the one-shot exec path) ---


async def test_run_command_output_cap_bounds_buffer() -> None:
    # Produce far more than the cap; only `cap` bytes are buffered/returned, yet
    # the command still runs to completion (exit 0) — memory is bounded, not the
    # command. Pre-fix the full output was buffered in relay memory.
    out, code = await run_command(
        "head -c 200000 /dev/zero | tr '\\0' x", timeout=10, output_cap=1000
    )
    assert code == 0
    assert len(out.encode("utf-8")) <= 1000


async def test_run_command_output_cap_none_is_unbounded() -> None:
    # The historical behaviour is preserved when no cap is supplied.
    out, code = await run_command(
        "head -c 5000 /dev/zero | tr '\\0' y", timeout=10, output_cap=None
    )
    assert code == 0
    assert out.count("y") == 5000


async def test_run_command_output_cap_preserves_exit_code() -> None:
    # A lot of output, THEN a nonzero exit: the exit code must survive the cap
    # (we drain to EOF and reap the child rather than killing it at the cap).
    out, code = await run_command(
        "head -c 80000 /dev/zero | tr '\\0' z; exit 3", timeout=10, output_cap=500
    )
    assert code == 3
    assert len(out.encode("utf-8")) <= 500


async def test_run_command_output_cap_with_stdin() -> None:
    # stdin still feeds under a cap (concurrent feed + drain).
    out, code = await run_command("cat", timeout=10, stdin="piped-in\n", output_cap=1000)
    assert code == 0
    assert "piped-in" in out


async def test_run_command_large_stdin_with_cap_no_deadlock() -> None:
    # A stdin larger than a pipe buffer must not deadlock a bounded output drain:
    # feed and drain run concurrently. `cat` echoes it back, capped.
    big = "A" * 500000
    out, code = await run_command("cat", timeout=15, stdin=big, output_cap=2000)
    assert code == 0
    assert len(out.encode("utf-8")) <= 2000


async def test_run_command_output_cap_shared_across_streams() -> None:
    # merge_stderr=False: stdout and stderr share ONE budget, combined <= cap.
    cmd = "head -c 8000 /dev/zero | tr '\\0' o; head -c 8000 /dev/zero | tr '\\0' e 1>&2"
    out, code = await run_command(cmd, timeout=10, merge_stderr=False, output_cap=4000)
    assert code == 0
    assert len(out.encode("utf-8")) <= 4000


async def test_run_script_output_cap_bounds_buffer() -> None:
    out, code = await run_script(
        "head -c 200000 /dev/zero | tr '\\0' X",
        interpreter="bash",
        timeout=15,
        output_cap=1000,
    )
    assert code == 0
    assert len(out.encode("utf-8")) <= 1000
