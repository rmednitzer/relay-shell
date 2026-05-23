"""Tests for the `ssh_fanout` tool (B-002).

We monkeypatch `Relay.ssh.run` for these tests so the parallel
dispatch / per-host result aggregation can be exercised without an
in-process SSH server. The real SshPool path is covered separately
by `tests/test_ssh_integration.py`.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from relay_shell.config import Settings
from relay_shell.policy import Policy, Tier, classify
from relay_shell.server import build_server


def _audit_lines(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


def _text(content: object) -> str:
    return "".join(b.text for b in content if getattr(b, "type", "") == "text")


@pytest.fixture
def fanout_settings(tmp_path: Path) -> Settings:
    # Populate an inventory so ssh_fanout's "use the whole inventory"
    # branch has something to iterate.
    inv = tmp_path / "inv.json"
    # Inventory file format is a flat object keyed by host alias.
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
    # A neutral command classifies as Tier 1; the existing TIER patterns
    # escalate based on the command, not the tool name.
    assert classify("ssh_fanout", "uptime") is Tier.REVERSIBLE


def test_ssh_fanout_classification_follows_command_severity() -> None:
    # Tier 3 verbs in the command escalate ssh_fanout to IRREVERSIBLE.
    assert classify("ssh_fanout", "rm -rf /tmp/x") is Tier.IRREVERSIBLE
    # Tier 2 verbs escalate to STATEFUL.
    assert classify("ssh_fanout", "systemctl restart nginx") is Tier.STATEFUL
    # Privilege escalation also escalates.
    assert classify("ssh_fanout", "sudo apt-get install foo") is Tier.STATEFUL


def test_ssh_fanout_denied_in_readonly_mode() -> None:
    # ssh_fanout runs arbitrary commands and is therefore NOT Tier 0.
    p = Policy("readonly")
    d = p.check("ssh_fanout", "uptime")
    assert d.allowed is False
    assert d.tier is Tier.REVERSIBLE


async def test_ssh_fanout_runs_command_across_inventory(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Patch SshPool.run on the *instance* so each host call returns a
    # synthetic (output, exit_code). The patched run records the call
    # order, so we can assert all three inventory hosts were hit.
    called: list[str] = []

    async def fake_run(
        _self: Any,
        host: str,
        _command: str,
        *,
        timeout: int,
        connect_kwargs: dict[str, Any],
    ) -> tuple[str, int | None]:
        called.append(host)
        return (f"out-from-{host}\n", 0)

    mcp = build_server(fanout_settings)
    # The Relay instance is captured by the tool closure; reach it by
    # name from the registered tools' shared state. Easier: monkeypatch
    # SshPool.run on the class so every SshPool instance picks it up.
    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    content, _ = await mcp.call_tool("ssh_fanout", {"command": "uptime", "concurrency": 2})
    payload = json.loads(_text(content))
    assert payload["command"] == "uptime"
    assert payload["concurrency"] == 2
    assert payload["host_count"] == 3
    # All inventory hosts were dispatched.
    hosts_returned = sorted(r["host"] for r in payload["results"])
    assert hosts_returned == ["host-a", "host-b", "host-c"]
    # Every result carries an exit code and the synthetic output.
    for rec in payload["results"]:
        assert rec["exit_code"] == 0
        assert f"out-from-{rec['host']}" in rec["output"]
    # The fake was called once per host.
    assert sorted(called) == ["host-a", "host-b", "host-c"]


async def test_ssh_fanout_explicit_host_list_overrides_inventory(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_run(_self: Any, host: str, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        return (f"out-{host}", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    # Two explicit hosts (neither in the inventory) — the wrapper must
    # use the explicit list, not fall back to inventory.
    content, _ = await mcp.call_tool(
        "ssh_fanout",
        {"command": "uptime", "hosts": "ad-hoc-1, ad-hoc-2"},
    )
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
    ) -> tuple[str, int | None]:
        if host == "host-b":
            raise OSError("connection refused")
        return ("ok", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    content, _ = await mcp.call_tool("ssh_fanout", {"command": "uptime"})
    payload = json.loads(_text(content))
    by_host = {r["host"]: r for r in payload["results"]}
    assert by_host["host-a"]["exit_code"] == 0
    assert by_host["host-c"]["exit_code"] == 0
    # The failing host's record has exit_code=None and a structured
    # UNREACHABLE marker in the output.
    assert by_host["host-b"]["exit_code"] is None
    assert "UNREACHABLE" in by_host["host-b"]["output"]
    assert "OSError" in by_host["host-b"]["output"]


async def test_ssh_fanout_concurrency_is_bounded(
    fanout_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Track peak concurrent calls inside fake_run.
    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    async def fake_run(_self: Any, host: str, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        nonlocal in_flight, peak
        async with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        # Hold the slot briefly so concurrent calls actually overlap.
        await asyncio.sleep(0.02)
        async with lock:
            in_flight -= 1
        return ("ok", 0)

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(fanout_settings)
    # Request concurrency=2 across the 3 inventory hosts. Peak must
    # not exceed 2.
    await mcp.call_tool("ssh_fanout", {"command": "uptime", "concurrency": 2})
    assert peak <= 2


async def test_ssh_fanout_rejects_oversize_host_list(fanout_settings: Settings) -> None:
    # The wrapper caps `len(host_list)` at 100. A larger list
    # short-circuits before any SSH call is dispatched.
    mcp = build_server(fanout_settings)
    too_many = ",".join(f"host{i}.example" for i in range(101))
    content, _ = await mcp.call_tool("ssh_fanout", {"command": "uptime", "hosts": too_many})
    text = _text(content)
    assert "exceeds the per-call cap" in text
    assert "101 hosts" in text


async def test_ssh_fanout_no_hosts_no_inventory(tmp_path: Path) -> None:
    # Empty inventory + empty `hosts` argument: tool returns a clear
    # message rather than zero work.
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
    content, _ = await mcp.call_tool("ssh_fanout", {"command": "uptime"})
    assert "no hosts configured" in _text(content)


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
    # The deny list is the security guarantee. ssh_fanout must run its
    # command through the same policy_text path as ssh_exec so that an
    # operator's RELAY_SHELL_POLICY_DENY rejects fan-out calls the
    # same way it rejects single-host calls.
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

    # SSH must never be reached - the deny check rejects before _work.
    async def fake_run(_self: Any, *_a: Any, **_k: Any) -> tuple[str, int | None]:
        pytest.fail("ssh.run was called despite the deny list")
        return ("", 0)  # unreachable

    from relay_shell.sshpool import SshPool

    monkeypatch.setattr(SshPool, "run", fake_run)

    mcp = build_server(settings)
    content, _ = await mcp.call_tool("ssh_fanout", {"command": "rm -rf /tmp/x", "hosts": "h1"})
    text = _text(content)
    assert "DENIED" in text
    assert "RELAY_SHELL_POLICY_DENY" in text
