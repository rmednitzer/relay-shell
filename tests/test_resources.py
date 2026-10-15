"""Tests for the MCP resources exposed by `build_server`.

Resources are read-only context the client can list and read on its own.
Three are registered:

  - `relay-shell://inventory`           full host list
  - `relay-shell://inventory/{host}`    one host's resolved spec
  - `relay-shell://ssh-config`          ssh_config metadata (path + aliases)

Each read is audited (tier 0). The audit `tool` field is stable per
resource (no user-controlled data interpolated):

  - ``resource:inventory``        for the flat list
  - ``resource:inventory_host``   for the templated read (host in `args`)
  - ``resource:ssh-config``       for the config metadata

Resource reads do not go through ``Relay.run``, which is for tool calls
that need policy admission, timeouts and exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

from helpers import audit_lines as _audit_lines
from relay_shell.config import Settings
from relay_shell.server import build_server


def _read(content) -> str:
    """Pull the text body off a `read_resource` result."""
    items = list(content)
    assert items, "read_resource returned no contents"
    item = items[0]
    body = item.content
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    return body


def _settings_with_inventory(tmp_path: Path, inventory: dict) -> Settings:
    inv_file = tmp_path / "inv.json"
    inv_file.write_text(json.dumps(inventory))
    return Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=0,
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory=str(inv_file),
        auth_state_dir=str(tmp_path / "oauth"),
    )


# --- resource://inventory ---------------------------------------------------


async def test_inventory_resource_returns_host_list(tmp_path: Path) -> None:
    cfg = _settings_with_inventory(
        tmp_path,
        {
            "web-01": {"hostname": "10.0.0.1", "user": "ops", "port": 22},
            "db-01": {"hostname": "10.0.0.2", "user": "ops"},
        },
    )
    mcp = build_server(cfg)
    body = _read(await mcp.read_resource("relay-shell://inventory"))
    data = json.loads(body)
    assert isinstance(data, list)
    names = {h["name"] for h in data}
    assert names == {"web-01", "db-01"}
    # The source label tells a client where a spec came from.
    assert all(h["source"] == "inventory" for h in data)


async def test_inventory_resource_audited_tier_zero(tmp_path: Path) -> None:
    cfg = _settings_with_inventory(tmp_path, {"a": {"hostname": "1.1.1.1"}})
    mcp = build_server(cfg)
    await mcp.read_resource("relay-shell://inventory")
    lines = _audit_lines(Path(cfg.audit_path))
    matching = [e for e in lines if e["tool"] == "resource:inventory"]
    assert len(matching) == 1
    assert matching[0]["tier"] == 0
    assert matching[0]["denied"] is False
    # The output body is never written, only its hash and length.
    assert "output_sha256" in matching[0]
    assert "args" in matching[0] and matching[0]["args"] == {}


# --- resource://inventory/{host} -------------------------------------------


async def test_inventory_host_resource_returns_known_host(tmp_path: Path) -> None:
    cfg = _settings_with_inventory(
        tmp_path, {"foo": {"hostname": "10.0.0.99", "user": "deploy", "port": 2222}}
    )
    mcp = build_server(cfg)
    body = _read(await mcp.read_resource("relay-shell://inventory/foo"))
    spec = json.loads(body)
    assert spec["name"] == "foo"
    assert spec["hostname"] == "10.0.0.99"
    assert spec["user"] == "deploy"
    assert spec["port"] == 2222


async def test_inventory_host_resource_passthrough_unknown(tmp_path: Path) -> None:
    # An unknown alias yields a passthrough spec (asyncssh would resolve it).
    cfg = _settings_with_inventory(tmp_path, {})
    mcp = build_server(cfg)
    body = _read(await mcp.read_resource("relay-shell://inventory/not-registered"))
    spec = json.loads(body)
    assert spec["name"] == "not-registered"
    assert spec["hostname"] == "not-registered"
    # Passthrough specs default to source="explicit", distinguishing them
    # from inventory-backed entries.
    assert spec["source"] == "explicit"


async def test_inventory_host_resource_audited_with_stable_tool_name(tmp_path: Path) -> None:
    # The audit `tool` is the stable name (no host interpolated); the host
    # moves into `args` so redaction runs and tool-name cardinality stays
    # bounded.
    cfg = _settings_with_inventory(tmp_path, {"x": {"hostname": "h"}})
    mcp = build_server(cfg)
    await mcp.read_resource("relay-shell://inventory/x")
    lines = _audit_lines(Path(cfg.audit_path))
    matching = [e for e in lines if e["tool"] == "resource:inventory_host"]
    assert len(matching) == 1
    assert matching[0]["tier"] == 0
    assert matching[0]["args"] == {"host": "x"}


# --- resource://ssh-config --------------------------------------------------


async def test_ssh_config_resource_reports_path_and_aliases(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sshconfig"
    cfg_file.write_text(
        "Host alpha\n"
        "  HostName 10.0.0.10\n"
        "Host beta gamma\n"
        "  HostName 10.0.0.20\n"
        "Host *\n"
        "  ServerAliveInterval 60\n"
    )
    cfg = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=0,
        ssh_config=str(cfg_file),
        inventory="",
        auth_state_dir=str(tmp_path / "oauth"),
    )
    mcp = build_server(cfg)
    body = _read(await mcp.read_resource("relay-shell://ssh-config"))
    payload = json.loads(body)
    assert payload["path"] == str(cfg_file)
    # Wildcard aliases are excluded; both aliases on the `Host beta gamma`
    # line are listed.
    assert payload["aliases"] == ["alpha", "beta", "gamma"]


async def test_ssh_config_resource_when_no_file(tmp_path: Path) -> None:
    cfg = _settings_with_inventory(tmp_path, {})
    mcp = build_server(cfg)
    body = _read(await mcp.read_resource("relay-shell://ssh-config"))
    payload = json.loads(body)
    # Missing config file: path is null and aliases empty, as valid JSON
    # rather than an exception into the transport.
    assert payload["path"] is None
    assert payload["aliases"] == []


async def test_ssh_config_resource_audited(tmp_path: Path) -> None:
    cfg = _settings_with_inventory(tmp_path, {})
    mcp = build_server(cfg)
    await mcp.read_resource("relay-shell://ssh-config")
    lines = _audit_lines(Path(cfg.audit_path))
    matching = [e for e in lines if e["tool"] == "resource:ssh-config"]
    assert len(matching) == 1
    assert matching[0]["tier"] == 0


async def test_ssh_config_aliases_survive_inventory_override(tmp_path: Path) -> None:
    # The resource must list aliases declared in the active ssh_config even
    # when an inventory entry overrides the same alias. Regression: filtering
    # merged hosts by source=="ssh_config" silently dropped them.
    cfg_file = tmp_path / "sshconfig"
    cfg_file.write_text("Host shared\n  HostName 10.0.0.1\n")
    inv_file = tmp_path / "inv.json"
    inv_file.write_text(json.dumps({"shared": {"hostname": "10.99.99.99"}}))
    cfg = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=0,
        ssh_config=str(cfg_file),
        inventory=str(inv_file),
        auth_state_dir=str(tmp_path / "oauth"),
    )
    mcp = build_server(cfg)
    body = _read(await mcp.read_resource("relay-shell://ssh-config"))
    payload = json.loads(body)
    assert "shared" in payload["aliases"]


# --- output cap ------------------------------------------------------------


async def test_inventory_resource_is_bounded_by_max_output(tmp_path: Path) -> None:
    # A very large inventory must not yield an unbounded response: the
    # resource applies the same `clamp_output(max_output)` cap as tools.
    inventory = {f"host-{i:05d}": {"hostname": f"10.0.{i // 250}.{i % 250}"} for i in range(2000)}
    cfg = _settings_with_inventory(tmp_path, inventory)
    # A tiny cap makes the truncation path deterministic.
    cfg = cfg.model_copy(update={"max_output": 2048})
    mcp = build_server(cfg)
    body = _read(await mcp.read_resource("relay-shell://inventory"))
    assert "[TRUNCATED" in body
    # Under the cap plus the marker's small overhead.
    assert len(body.encode("utf-8")) < 4096
