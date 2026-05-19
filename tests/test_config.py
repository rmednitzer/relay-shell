from __future__ import annotations

import pytest
from pydantic import ValidationError

from relay_shell.config import Settings


def test_defaults(clean_env: None) -> None:
    s = Settings()
    assert s.transport == "stdio"
    assert s.policy_mode == "open"
    assert s.max_timeout >= s.default_timeout


def test_env_override(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_SHELL_TRANSPORT", "http")
    monkeypatch.setenv("RELAY_SHELL_POLICY_MODE", "guarded")
    monkeypatch.setenv("RELAY_SHELL_HTTP_PORT", "9000")
    s = Settings()
    assert s.transport == "http"
    assert s.policy_mode == "guarded"
    assert s.http_port == 9000


def test_invalid_transport(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_SHELL_TRANSPORT", "carrier-pigeon")
    with pytest.raises(ValidationError):
        Settings()


def test_invalid_known_hosts(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_SHELL_SSH_KNOWN_HOSTS", "whatever")
    with pytest.raises(ValidationError):
        Settings()
