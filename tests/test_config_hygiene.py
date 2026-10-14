"""A14-C11: a mistyped RELAY_SHELL_* name must not silently fall back to a default."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from relay_shell.config import Settings, get_settings, unknown_settings_names


def test_typo_is_reported_with_a_suggestion() -> None:
    found = unknown_settings_names({"RELAY_SHELL_POLICY_MOD": "guarded", "PATH": "/bin"})
    assert found == [("RELAY_SHELL_POLICY_MOD", "RELAY_SHELL_POLICY_MODE")]


def test_known_names_any_case_and_foreign_variables_are_quiet() -> None:
    env = {
        "RELAY_SHELL_POLICY_MODE": "guarded",
        "relay_shell_max_timeout": "10",
        "RELAY_SHELL_EDGE_DOMAIN": "relay.example.org",  # installer variable, not a Settings field
        "RELAY_SHELLFISH": "x",  # not under the prefix
        "HOME": "/root",
    }
    assert unknown_settings_names(env) == []


def test_every_settings_field_is_known() -> None:
    env = {f"RELAY_SHELL_{n.upper()}": "x" for n in Settings.model_fields}
    assert unknown_settings_names(env) == []


def test_unknown_name_without_a_close_match_has_no_suggestion() -> None:
    assert unknown_settings_names({"RELAY_SHELL_ZZZZZZZZZZZZ": "1"}) == [
        ("RELAY_SHELL_ZZZZZZZZZZZZ", None)
    ]


def test_dotenv_file_is_checked_too(tmp_path: Path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "# comment\nexport RELAY_SHELL_POLICY_DENY_=x\nRELAY_SHELL_MAX_OUTPUT=2048\n\nbad line\n"
    )
    assert unknown_settings_names({}, dotenv=dotenv) == [
        ("RELAY_SHELL_POLICY_DENY_", "RELAY_SHELL_POLICY_DENY")
    ]
    assert unknown_settings_names({}, dotenv=tmp_path / "missing.env") == []


def test_get_settings_warns_once_for_a_typo(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)  # no stray .env
    monkeypatch.setenv("RELAY_SHELL_POLICY_MOD", "readonly")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="relay_shell.config"):
            settings = get_settings()
            get_settings()
    finally:
        get_settings.cache_clear()
    assert settings.policy_mode == "open", "the typo leaves the default in force"
    messages = [r.getMessage() for r in caplog.records if r.name == "relay_shell.config"]
    assert len(messages) == 1
    assert "RELAY_SHELL_POLICY_MOD" in messages[0]
    assert "RELAY_SHELL_POLICY_MODE" in messages[0]


def test_default_timeout_is_applied_when_the_caller_omits_it(settings: Settings) -> None:
    from relay_shell.server import Relay

    relay = Relay(settings.model_copy(update={"default_timeout": 7, "max_timeout": 100}))
    assert relay.exec_timeout(0) == 7
    assert relay.exec_timeout(5) == 5
    assert relay.exec_timeout(500) == 100
    capped = Relay(settings.model_copy(update={"default_timeout": 900, "max_timeout": 100}))
    assert capped.exec_timeout(0) == 100, "the default is still clamped to the maximum"


async def test_shell_exec_uses_the_configured_default(settings: Settings) -> None:
    """End to end through the registered tool: omitting ``timeout`` enforces the default."""
    import time

    from relay_shell.server import build_server

    cfg = settings.model_copy(update={"default_timeout": 1, "max_timeout": 30})
    server = build_server(cfg)
    started = time.monotonic()
    result = await server.call_tool("shell_exec", {"command": "sleep 10"})
    assert time.monotonic() - started < 8
    assert "TIMEOUT after 1s" in str(result)
