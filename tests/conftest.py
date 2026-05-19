"""Shared fixtures. Nothing here touches the network or real credentials."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from mcpx.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=0,
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory="",
        auth_state_dir=str(tmp_path / "oauth"),
    )


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in list(__import__("os").environ):
        if key.startswith("MCPX_"):
            monkeypatch.delenv(key, raising=False)
    yield
