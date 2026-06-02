from __future__ import annotations

import pytest
from pydantic import ValidationError

from relay_shell.config import Settings


def test_defaults(clean_env: None) -> None:
    s = Settings()
    assert s.transport == "stdio"
    assert s.policy_mode == "open"
    assert s.max_timeout >= s.default_timeout
    assert s.audit_format == "jsonl"


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


def test_invalid_audit_format(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_SHELL_AUDIT_FORMAT", "syslog")
    with pytest.raises(ValidationError):
        Settings()


def test_audit_chain_off_by_default(clean_env: None) -> None:
    assert Settings().audit_chain is False


def test_audit_chain_with_jsonl_is_accepted(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELAY_SHELL_AUDIT_CHAIN", "true")  # jsonl is the default
    s = Settings()
    assert s.audit_chain is True
    assert s.audit_format == "jsonl"


def test_audit_chain_requires_jsonl_format(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The chain is resumed by re-parsing the last jsonl line; cef/leef cannot
    # be resumed, so the combination must fail fast at startup.
    monkeypatch.setenv("RELAY_SHELL_AUDIT_CHAIN", "true")
    monkeypatch.setenv("RELAY_SHELL_AUDIT_FORMAT", "cef")
    with pytest.raises(ValidationError):
        Settings()


def test_seccomp_notify_off_by_default(clean_env: None) -> None:
    s = Settings()
    assert s.seccomp_notify is False
    assert s.seccomp_notify_cap == 256


def test_seccomp_notify_env_override(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_SHELL_SECCOMP_NOTIFY", "true")
    monkeypatch.setenv("RELAY_SHELL_SECCOMP_NOTIFY_CAP", "64")
    s = Settings()
    assert s.seccomp_notify is True
    assert s.seccomp_notify_cap == 64


def test_seccomp_notify_cap_floor(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_SHELL_SECCOMP_NOTIFY_CAP", "0")
    with pytest.raises(ValidationError):
        Settings()
