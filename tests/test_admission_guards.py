"""Admission guards (audit M4 / M5 / M7, 2026-10-04)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from relay_shell.__main__ import main
from relay_shell.config import Settings, get_settings
from relay_shell.inventory import Inventory
from relay_shell.policy import Policy, Tier
from relay_shell.server import build_server


def _text(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def _audit(settings: Settings) -> list[dict[str, Any]]:
    path = Path(settings.audit_path)
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]


# --- M4: the text put in front of the policy layer is bounded -----------------


def test_max_input_default_and_bounds() -> None:
    assert Settings().max_input == 2_097_152
    with pytest.raises(ValueError):
        Settings(max_input=10)  # below the 1 KiB floor
    with pytest.raises(ValueError):
        Settings(max_input=10**10)


async def test_oversized_input_is_refused_before_it_is_scanned(settings: Settings) -> None:
    cfg = settings.model_copy(update={"max_input": 1024})
    mcp = build_server(cfg)
    padded = "x" * 2000 + "; rm -rf /"  # the dangerous part sits past any partial scan window
    out = _text(await mcp.call_tool("shell_exec", {"command": "echo ok", "stdin": padded}))
    assert out.startswith("[DENIED tier 1 (REVERSIBLE): input is ")
    assert "RELAY_SHELL_MAX_INPUT (1024)" in out

    (rec,) = _audit(cfg)
    assert rec["tool"] == "shell_exec" and rec["denied"] is True
    assert len(rec["args"]["stdin"]) < 700  # the audited copy stays bounded
    counters = mcp.relay.metrics.snapshot_counters()["relay_shell_tool_calls_total"]  # type: ignore[attr-defined]
    assert (
        counters[(("mode", "open"), ("outcome", "denied"), ("tier", "1"), ("tool", "shell_exec"))]
        == 1
    )


async def test_input_at_the_limit_is_still_admitted(settings: Settings) -> None:
    cfg = settings.model_copy(update={"max_input": 1024})
    mcp = build_server(cfg)
    command = "echo " + "a" * (1024 - len("echo "))
    assert len(command) == 1024
    out = _text(await mcp.call_tool("shell_exec", {"command": command}))
    assert "DENIED" not in out and out.startswith("[exit 0]")


async def test_the_cap_covers_session_input_too(settings: Settings) -> None:
    cfg = settings.model_copy(update={"max_input": 1024})
    mcp = build_server(cfg)
    spawn = _text(await mcp.call_tool("shell_spawn", {"command": "/bin/sh"}))
    sid = spawn.split("session ", 1)[1].split()[0]
    try:
        out = _text(await mcp.call_tool("session_send", {"session_id": sid, "data": "y" * 5000}))
        assert out.startswith("[DENIED")
    finally:
        await mcp.call_tool("session_kill", {"session_id": sid})


# --- M5: unauthenticated HTTP off loopback is refused at startup --------------


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "127.5.5.5", "::1", "[::1]", "localhost", "LOCALHOST"]
)
def test_loopback_http_without_auth_is_fine(host: str) -> None:
    assert Settings(transport="http", http_host=host).http_host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "relay.example.org"])
def test_network_http_without_auth_is_refused(host: str) -> None:
    with pytest.raises(ValueError, match="refusing to serve HTTP"):
        Settings(transport="http", http_host=host)


def test_network_http_is_allowed_with_auth_or_an_explicit_override() -> None:
    assert Settings(transport="http", http_host="0.0.0.0", auth_enabled=True)
    assert Settings(
        transport="http",
        http_host="0.0.0.0",
        allow_unauth_network=True,
    )
    assert Settings(transport="stdio", http_host="0.0.0.0")  # no listener at all


def test_startup_reports_the_refusal_as_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("RELAY_SHELL_TRANSPORT", "http")
    monkeypatch.setenv("RELAY_SHELL_HTTP_HOST", "0.0.0.0")
    get_settings.cache_clear()
    try:
        assert main(["--check-config"]) == 2
        assert "refusing to serve HTTP" in capsys.readouterr().err
    finally:
        get_settings.cache_clear()


# --- M7: ssh_check probes the inventory freely, other hosts count as Tier 1 ----


def test_policy_min_tier_raises_but_never_lowers() -> None:
    readonly = Policy("readonly")
    assert readonly.check("ssh_check", "web1").allowed
    refused = readonly.check("ssh_check", "web1", Tier.REVERSIBLE)
    assert not refused.allowed and refused.tier is Tier.REVERSIBLE
    assert Policy("open").check("ssh_check", "web1", Tier.REVERSIBLE).allowed
    # A higher tier from the text is never lowered by a lower floor.
    assert Policy("open").check("shell_exec", "rm -rf /x", Tier.READ_ONLY).tier is Tier.IRREVERSIBLE


def test_inventory_knows_aliases_and_hostnames(tmp_path: Path) -> None:
    inv_file = tmp_path / "inv.json"
    inv_file.write_text(json.dumps({"web1": {"hostname": "10.0.0.5"}}))
    inv = Inventory(str(tmp_path / "none"), str(inv_file)).load()
    assert inv.knows("web1") and inv.knows("10.0.0.5")
    assert not inv.knows("evil.example") and not inv.knows("root@web1")


async def test_readonly_ssh_check_allows_the_inventory_and_refuses_other_hosts(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inv_file = tmp_path / "inv.json"
    inv_file.write_text(json.dumps({"web1": {"hostname": "10.0.0.5"}}))
    cfg = settings.model_copy(update={"policy_mode": "readonly", "inventory": str(inv_file)})
    mcp = build_server(cfg)
    probed: list[str] = []

    async def fake_run(name: str, *_a: object, **_k: object) -> tuple[str, int | None]:
        probed.append(name)
        return ("ok\n", 0)

    monkeypatch.setattr(mcp.relay.ssh, "run", fake_run)  # type: ignore[attr-defined]

    assert "web1: ok" in _text(await mcp.call_tool("ssh_check", {"hosts": "web1"}))
    assert "web1: ok" in _text(await mcp.call_tool("ssh_check", {"hosts": ""}))  # whole inventory
    assert "10.0.0.5: ok" in _text(await mcp.call_tool("ssh_check", {"hosts": "10.0.0.5"}))
    assert probed == ["web1", "web1", "10.0.0.5"]

    for hosts in ("evil.example", "web1,evil.example", "root@web1"):
        out = _text(await mcp.call_tool("ssh_check", {"hosts": hosts}))
        assert out.startswith("[DENIED tier 1 (REVERSIBLE): readonly mode"), (hosts, out)
    assert probed == ["web1", "web1", "10.0.0.5"]  # nothing was dialled for the refused ones


async def test_open_mode_ssh_check_is_unchanged_for_any_host(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcp = build_server(settings)

    async def fake_run(name: str, *_a: object, **_k: object) -> tuple[str, int | None]:
        return ("ok\n", 0)

    monkeypatch.setattr(mcp.relay.ssh, "run", fake_run)  # type: ignore[attr-defined]
    out = _text(await mcp.call_tool("ssh_check", {"hosts": "anything.example"}))
    assert "anything.example: ok" in out
