"""Tests for the `ssh_fanout` tool (B-002).

`Relay.ssh.run` is monkeypatched so parallel dispatch and per-host result
aggregation run without an in-process SSH server. The real SshPool path is
covered by `tests/test_ssh_integration.py`.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from helpers import audit_lines as _audit_lines
from helpers import text as _text
from relay_shell.config import Settings
from relay_shell.policy import Policy, Tier, classify
from relay_shell.server import _SSH_FANOUT_MAX_HOSTS, build_server


@pytest.fixture
def fanout_settings(tmp_path: Path) -> Settings:
    # Inventory for ssh_fanout's "whole inventory" branch: a flat object keyed by alias.
    inv = tmp_path / "inv.json"
    inv.write_text(
        json.dumps(
            {
                "host-a": {"hostname": "1.2.3.4"},
                "host-b": {"hostname": "5.6.7.8"},
                "host-c": {"hostname": "9.10.11.12"},
            }
        )
    )
    return Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=0,
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory=str(inv),
        auth_state_dir=str(tmp_path / "oauth"),
    )


def test_ssh_fanout_classified_tier_one_by_default() -> None:
    # Escalation follows the command, not the tool name.
    assert classify("ssh_fanout", "uptime") is Tier.REVERSIBLE


def test_ssh_fanout_classification_follows_command_severity() -> None:
    assert classify("ssh_fanout", "rm -rf /tmp/x") is Tier.IRREVERSIBLE
    assert classify("ssh_fanout", "systemctl restart nginx") is Tier.STATEFUL
    assert classify("ssh_fanout", "sudo apt-get install foo") is Tier.STATEFUL


def test_ssh_fanout_denied_in_readonly_mode() -> None:
    # ssh_fanout runs arbitrary commands, so it is not Tier 0.
    p = Policy("readonly")
    d = p.check("ssh_fanout", "uptime")
    assert d.allowed is False
    assert d.tier is Tier.REVERSIBLE


async def test_ssh_fanout_runs_command_across_inventory(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each host call returns synthetic output; `called` records the hosts hit.
    called: list[str] = []

    async def fake_run(
        _self: Any,
        host: str,
        _command: str,
        *,
        timeout: int,
        connect_kwargs: dict[str, Any],
        **_k: Any,
    ) -> tuple[str, int | None]:
        called.append(host)
        return (f"out-from-{host}\n", 0)

    mcp = build_server(fanout_settings)
    # The Relay instance is captured by the tool closure, so patch the class.
    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    content = (await mcp.call_tool("ssh_fanout", {"command": "uptime", "concurrency": 2})).content
    payload = json.loads(_text(content))
    assert payload["command"] == "uptime"
    assert payload["concurrency"] == 2
    assert payload["host_count"] == 3
    hosts_returned = sorted(r["host"] for r in payload["results"])
    assert hosts_returned == ["host-a", "host-b", "host-c"]
    for rec in payload["results"]:
        assert rec["exit_code"] == 0
        assert f"out-from-{rec['host']}" in rec["output"]
    assert sorted(called) == ["host-a", "host-b", "host-c"]


async def test_ssh_fanout_explicit_host_list_overrides_inventory(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_run(_self: Any, host: str, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        return (f"out-{host}", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    # Neither host is in the inventory: the explicit list must be used.
    content = (
        await mcp.call_tool(
            "ssh_fanout",
            {"command": "uptime", "hosts": "ad-hoc-1, ad-hoc-2"},
        )
    ).content
    payload = json.loads(_text(content))
    assert payload["host_count"] == 2
    assert sorted(r["host"] for r in payload["results"]) == ["ad-hoc-1", "ad-hoc-2"]


async def test_ssh_fanout_surfaces_per_host_failure(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_run(
        _self: Any,
        host: str,
        _command: str,
        *,
        timeout: int,
        connect_kwargs: dict[str, Any],
        **_k: Any,
    ) -> tuple[str, int | None]:
        if host == "host-b":
            raise OSError("connection refused")
        return ("ok", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    content = (await mcp.call_tool("ssh_fanout", {"command": "uptime"})).content
    payload = json.loads(_text(content))
    by_host = {r["host"]: r for r in payload["results"]}
    assert by_host["host-a"]["exit_code"] == 0
    assert by_host["host-c"]["exit_code"] == 0
    # The failing host has exit_code=None and a structured UNREACHABLE marker.
    assert by_host["host-b"]["exit_code"] is None
    assert "UNREACHABLE" in by_host["host-b"]["output"]
    assert "OSError" in by_host["host-b"]["output"]


async def test_ssh_fanout_concurrency_is_bounded(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    async def fake_run(_self: Any, host: str, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        nonlocal in_flight, peak
        async with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        # Hold the slot so concurrent calls overlap.
        await asyncio.sleep(0.02)
        async with lock:
            in_flight -= 1
        return ("ok", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    # 3 inventory hosts, concurrency=2.
    await mcp.call_tool("ssh_fanout", {"command": "uptime", "concurrency": 2})
    assert peak <= 2


async def test_ssh_fanout_rejects_oversize_host_list(fanout_settings: Settings) -> None:
    # The cap is 100 hosts; a larger list is rejected before any SSH call.
    mcp = build_server(fanout_settings)
    too_many = ",".join(f"host{i}.example" for i in range(101))
    content = (await mcp.call_tool("ssh_fanout", {"command": "uptime", "hosts": too_many})).content
    text = _text(content)
    assert "exceeds the per-call cap" in text
    assert "101 hosts" in text


async def test_ssh_fanout_no_hosts_no_inventory(tmp_path: Path) -> None:
    # Empty inventory and empty `hosts`: a clear message, not zero work.
    settings = Settings(
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
    mcp = build_server(settings)
    content = (await mcp.call_tool("ssh_fanout", {"command": "uptime"})).content
    assert "no hosts configured" in _text(content)


async def test_ssh_fanout_output_stays_within_max_output(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression for the review on #31: at the maximum host count the JSON
    # envelope must stay parseable. Without bounded per-host output, exception
    # strings and command echo, Relay.run() would truncate the serialized JSON
    # mid-stream, breaking the one-JSON-object contract.
    big_output = "X" * 100_000

    async def fake_run(_self: Any, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        return (big_output, 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    hosts = ",".join(f"h{i}.example" for i in range(_SSH_FANOUT_MAX_HOSTS))
    mcp = build_server(fanout_settings)
    content = (await mcp.call_tool("ssh_fanout", {"command": "uptime", "hosts": hosts})).content
    text = _text(content)
    payload = json.loads(text)
    assert payload["host_count"] == _SSH_FANOUT_MAX_HOSTS
    assert len(payload["results"]) == _SSH_FANOUT_MAX_HOSTS
    # The payload fits under the wrapper's clamp_output, so Relay.run() did not truncate.
    assert len(text.encode("utf-8")) <= fanout_settings.max_output


async def test_ssh_fanout_truncates_unreachable_exception_messages(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # codex review P2 on #31: exception messages must also be bounded by
    # per_host_budget so a few long errors cannot blow the envelope.
    huge_exc_msg = "Y" * 100_000

    async def fake_run(_self: Any, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        raise OSError(huge_exc_msg)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    hosts = ",".join(f"h{i}.example" for i in range(_SSH_FANOUT_MAX_HOSTS))
    mcp = build_server(fanout_settings)
    content = (await mcp.call_tool("ssh_fanout", {"command": "uptime", "hosts": hosts})).content
    text = _text(content)
    payload = json.loads(text)
    assert len(text.encode("utf-8")) <= fanout_settings.max_output
    assert all("UNREACHABLE" in r["output"] for r in payload["results"])


async def test_ssh_fanout_records_raw_hosts_argument(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Copilot review on #31: when `hosts=""` triggers the inventory fallback, the
    # audit record keeps the caller-supplied value, not the resolved fallback.
    async def fake_run(_self: Any, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        return ("ok", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    await mcp.call_tool("ssh_fanout", {"command": "uptime"})
    last = _audit_lines(Path(fanout_settings.audit_path))[-1]
    assert last["args"]["hosts"] == ""  # raw input, NOT "inventory"


async def test_ssh_fanout_audits_its_args(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_run(_self: Any, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        return ("ok", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    await mcp.call_tool(
        "ssh_fanout",
        {"command": "uptime", "hosts": "h1,h2", "timeout": 12, "concurrency": 4},
    )
    last = _audit_lines(Path(fanout_settings.audit_path))[-1]
    assert last["tool"] == "ssh_fanout"
    assert last["args"]["command"] == "uptime"
    assert last["args"]["hosts"] == "h1,h2"
    assert last["args"]["timeout"] == 12
    assert last["args"]["concurrency"] == 4


async def test_ssh_fanout_deny_list_fires_on_command(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ssh_fanout must use the same policy_text path as ssh_exec so an operator's
    # RELAY_SHELL_POLICY_DENY rejects fan-out calls like single-host calls.
    settings = fanout_settings
    settings = Settings(
        transport=settings.transport,
        audit_path=settings.audit_path,
        policy_mode=settings.policy_mode,
        policy_deny=r"rm\s+-rf",
        ssh_known_hosts=settings.ssh_known_hosts,
        ssh_connect_timeout=settings.ssh_connect_timeout,
        ssh_keepalive=settings.ssh_keepalive,
        ssh_config=settings.ssh_config,
        inventory=settings.inventory,
        auth_state_dir=settings.auth_state_dir,
    )

    # The deny check rejects before _work, so SSH must never be reached.
    async def fake_run(_self: Any, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        pytest.fail("ssh.run was called despite the deny list")
        return ("", 0)  # unreachable

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(settings)
    content = (
        await mcp.call_tool("ssh_fanout", {"command": "rm -rf /tmp/x", "hosts": "h1"})
    ).content
    text = _text(content)
    assert "DENIED" in text
    assert "RELAY_SHELL_POLICY_DENY" in text
