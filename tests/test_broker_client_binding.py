"""A14-C10b: a confirmation token belongs to the client that planned the operation.

Without the binding, a second authenticated client issuing the identical call inside the TTL
could consume the token the first client had armed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from helpers import text as _text
from relay_shell.broker import ConfirmationBroker
from relay_shell.config import Settings
from relay_shell.server import build_server

# --- broker unit tests --------------------------------------------------


def test_other_client_cannot_consume_an_armed_token() -> None:
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "op", client_id="alice")
    assert b.arm(ch.token, client_id="alice") is True
    assert b.consume("shell_exec", "op", client_id="bob") is False
    # The refusal must not burn Alice's token.
    assert b.consume("shell_exec", "op", client_id="alice") is True


def test_other_client_cannot_arm_a_token_it_did_not_plan() -> None:
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "op", client_id="alice")
    assert b.arm(ch.token, client_id="bob") is False
    assert b.consume("shell_exec", "op", client_id="alice") is False, "still not armed"
    assert b.arm(ch.token, client_id="alice") is True
    assert b.consume("shell_exec", "op", client_id="alice") is True


def test_each_client_has_its_own_token_for_the_same_operation() -> None:
    b = ConfirmationBroker(ttl=120)
    a = b.plan("shell_exec", "op", client_id="alice")
    c = b.plan("shell_exec", "op", client_id="bob")
    assert b.arm(a.token, client_id="alice") and b.arm(c.token, client_id="bob")
    assert b.consume("shell_exec", "op", client_id="bob") is True
    assert b.consume("shell_exec", "op", client_id="alice") is True


def test_unauthenticated_callers_share_the_empty_identity() -> None:
    """stdio / no-auth deployments have no client id and keep the operation-only binding."""
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "op")
    assert b.arm(ch.token) is True
    assert b.consume("shell_exec", "op") is True


def test_an_authenticated_client_cannot_use_an_unauthenticated_token() -> None:
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "op")
    b.arm(ch.token)
    assert b.consume("shell_exec", "op", client_id="alice") is False


# --- through the tool wrappers -----------------------------------------


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory="",
        auth_state_dir=str(tmp_path / "oauth"),
        confirm_tier3=True,
        confirm_ttl=120,
    )


async def test_second_client_cannot_ride_the_first_clients_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    who = {"client": "alice"}

    def _token() -> AccessToken:
        return AccessToken(token="fixture", client_id=who["client"], scopes=["mcp:tools"])

    monkeypatch.setattr("relay_shell.server.get_access_token", _token)
    mcp = build_server(_settings(tmp_path))
    victim = tmp_path / "victim.txt"
    victim.write_text("data")
    cmd = f"rm -rf {victim}"

    # Alice plans and arms.
    r1 = _text((await mcp.call_tool("shell_exec", {"command": cmd})).content)
    assert "CONFIRM REQUIRED" in r1
    token = re.search(r'token="([A-Za-z0-9_-]+)"', r1).group(1)  # type: ignore[union-attr]
    assert "armed" in _text((await mcp.call_tool("operation_confirm", {"token": token})).content)

    # Bob replays the identical call: challenged, not executed, Alice's token untouched.
    who["client"] = "bob"
    r2 = _text((await mcp.call_tool("shell_exec", {"command": cmd})).content)
    assert "CONFIRM REQUIRED" in r2
    assert victim.exists(), "another client must not execute on Alice's confirmation"

    # Bob cannot arm Alice's token either.
    r3 = _text((await mcp.call_tool("operation_confirm", {"token": token})).content)
    assert "invalid or expired" in r3

    # Alice's armed token still works for Alice.
    who["client"] = "alice"
    r4 = _text((await mcp.call_tool("shell_exec", {"command": cmd})).content)
    assert "CONFIRM REQUIRED" not in r4
    assert not victim.exists()
