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
