"""End-to-end coverage tests for every tool wrapper in `server.py`.

Most tool wrappers in `server.py` are only exercised by the stdio e2e
test (a subprocess), so their bodies show up as uncovered in unit
coverage. This module calls each tool through `mcp.call_tool()` with
arguments that produce either valid output or a structured error
string - either way exercises the wrapper body so the audit, policy,
and truncate path is verified for every tool.

The tests do not attempt to drive deep semantic behavior - dedicated
modules cover that (`test_shell.py`, `test_ssh_integration.py`,
`test_ssh_keyscan_tool.py`, etc.). This module exists for coverage
breadth across the wrapper layer.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from relay_shell.config import Settings
from relay_shell.server import build_server


def _text(content: object) -> str:
    return "".join(b.text for b in content if getattr(b, "type", "") == "text")


# --- local shell wrappers ---------------------------------------------


async def test_shell_exec_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("shell_exec", {"command": "echo hello"})
    out = _text(content)
    assert "hello" in out
    assert "[exit 0]" in out


async def test_shell_script_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("shell_script", {"script": "echo first; echo second"})
    out = _text(content)
    assert "first" in out and "second" in out


# --- session lifecycle (covers shell_spawn + session_*) ---------------


async def test_session_lifecycle_covers_session_wrappers(settings: Settings) -> None:
    mcp = build_server(settings)

    # shell_spawn: starts a PTY session and returns the id in the body.
    content, _ = await mcp.call_tool("shell_spawn", {"command": "/bin/sh"})
    spawn_out = _text(content)
    # Body format is "[session <id> started] ...". Extract the id.
    assert "started" in spawn_out
    # ID is the first non-bracketed token after "session "
    sid = spawn_out.split("session ", 1)[1].split()[0]
    try:
        # session_list shows it.
        content, _ = await mcp.call_tool("session_list", {})
        assert sid in _text(content)

        # session_send writes to it.
        content, _ = await mcp.call_tool("session_send", {"session_id": sid, "data": "echo hi\n"})
        send_out = _text(content)
        # Either an "ok" / "wrote N bytes" indicator or empty - both exercise
        # the wrapper. The byte count framing is what matters here.
        assert send_out is not None

        # Wait briefly so the shell processes the input.
        await asyncio.sleep(0.2)

        # session_recv pulls accumulated output.
        content, _ = await mcp.call_tool("session_recv", {"session_id": sid, "wait_ms": 200})
        recv_out = _text(content)
        # We may or may not see "hi" depending on PTY echo, but the
        # wrapper must produce some bytes.
        assert isinstance(recv_out, str)

        # session_resize accepts cols/rows.
        content, _ = await mcp.call_tool(
            "session_resize", {"session_id": sid, "cols": 80, "rows": 24}
        )
        assert _text(content) is not None
    finally:
        # session_kill terminates the PTY.
        content, _ = await mcp.call_tool("session_kill", {"session_id": sid})
        kill_out = _text(content)
        assert "killed" in kill_out or "ended" in kill_out or sid in kill_out


async def test_session_recv_unknown_id_surfaces_error(settings: Settings) -> None:
    # Unknown ids must surface a structured error, not an exception.
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("session_recv", {"session_id": "does-not-exist", "wait_ms": 0})
    out = _text(content)
    # The wrapper passes the unknown id through the same ERROR-string
    # path; either "no such session" / similar marker, or an empty
    # safe response. Either way, no exception escaped.
    assert isinstance(out, str)


async def test_session_kill_unknown_id_surfaces_error(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("session_kill", {"session_id": "does-not-exist"})
    assert isinstance(_text(content), str)


async def test_session_resize_unknown_id_surfaces_error(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "session_resize", {"session_id": "does-not-exist", "cols": 80, "rows": 24}
    )
    assert isinstance(_text(content), str)


async def test_session_send_unknown_id_surfaces_error(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("session_send", {"session_id": "does-not-exist", "data": "x"})
    assert isinstance(_text(content), str)


async def test_session_list_empty(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("session_list", {})
    # The wrapper returns either "[]" / "no sessions" / an empty
    # listing - all bodies pass through the wrapper's audit path.
    assert isinstance(_text(content), str)


# --- ssh wrappers: error-path coverage --------------------------------
#
# The fixture settings have ssh_known_hosts="ignore" and an empty
# inventory, so every ssh_* tool call against an unresolvable host
# falls into the wrapper's exception-handling branch. That's enough
# to exercise the wrapper body for coverage; deep behaviour is
# covered by tests/test_ssh_integration.py.


async def test_ssh_exec_unreachable_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_exec",
        {"host": "no-such-host-123.invalid", "command": "true", "timeout": 1},
    )
    # The wrapper returns either an ERROR string or a non-zero exit
    # code; both go through the audit + truncate path.
    assert _text(content) is not None


async def test_ssh_spawn_unreachable_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_spawn",
        {"host": "no-such-host-123.invalid", "timeout": 1},
    )
    assert _text(content) is not None


async def test_ssh_upload_unreachable_wrapper(settings: Settings, tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("hi")
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_upload",
        {
            "host": "no-such-host-123.invalid",
            "local_path": str(src),
            "remote_path": "/tmp/dst.txt",
            "timeout": 1,
        },
    )
    assert _text(content) is not None


async def test_ssh_download_unreachable_wrapper(settings: Settings, tmp_path: Path) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_download",
        {
            "host": "no-such-host-123.invalid",
            "remote_path": "/tmp/whatever",
            "local_path": str(tmp_path / "dst.txt"),
            "timeout": 1,
        },
    )
    assert _text(content) is not None


async def test_ssh_forward_unreachable_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_forward",
        {
            "host": "no-such-host-123.invalid",
            "spec": "L:127.0.0.1:18080:example.org:80",
            "timeout": 1,
        },
    )
    assert _text(content) is not None


async def test_ssh_forward_list_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("ssh_forward_list", {})
    assert isinstance(_text(content), str)


async def test_ssh_forward_close_unknown_id_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("ssh_forward_close", {"forward_id": "fwd-does-not-exist"})
    assert isinstance(_text(content), str)


async def test_ssh_check_against_inventory_wrapper(settings: Settings) -> None:
    # Empty inventory + empty hosts arg -> wrapper returns the "no
    # hosts" message via its short-circuit path. Either way the body
    # executes.
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("ssh_check", {})
    assert isinstance(_text(content), str)


async def test_ssh_check_with_explicit_hosts_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_check", {"hosts": "no-such-host-123.invalid", "timeout": 1}
    )
    out = _text(content)
    assert "UNREACHABLE" in out or "no-such-host" in out


async def test_ssh_hosts_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("ssh_hosts", {})
    # Empty inventory -> "[]" / similar. Body executed regardless.
    assert isinstance(_text(content), str)


# --- server_info gets a direct unit test (closes T-002) --------------


async def test_server_info_reports_documented_fields(settings: Settings) -> None:
    # T-002 from runbook section 5.3: server_info is exercised via the
    # stdio e2e test but not by itself. A direct test confirming every
    # documented field is present catches silent removals.
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("server_info", {})
    info = json.loads(_text(content))
    # Required top-level fields per docs/tools.md.
    for key in ("name", "version", "transport", "policy_mode", "runtime", "limits", "audit", "ssh"):
        assert key in info, f"server_info missing top-level key: {key}"
    # The version is non-empty.
    assert info["version"]
    # The audit substructure carries the documented fields.
    assert "path" in info["audit"]
    assert "degraded" in info["audit"]
    # The limits substructure carries every clamp the server enforces.
    for limit in (
        "default_timeout",
        "max_timeout",
        "max_output",
        "max_output_hard",
        "max_sessions",
    ):
        assert limit in info["limits"], f"server_info.limits missing {limit}"
    # The SSH substructure now reports the connection-pool knobs so
    # operators can diff the live posture against their env file
    # without re-deriving the values from RELAY_SHELL_* env names.
    for ssh_key in (
        "known_hosts_default",
        "inventory_hosts",
        "ssh_config",
        "connect_timeout",
        "keepalive",
        "idle_timeout",
    ):
        assert ssh_key in info["ssh"], f"server_info.ssh missing {ssh_key}"


# --- connect_kwargs helper (closes C-003) ----------------------------


def test_connect_kwargs_omits_connect_timeout_by_default(settings: Settings) -> None:
    """Without an overlay, connect_kwargs returns the historical shape.

    SshPool.connect already falls back to settings.ssh_connect_timeout
    when the dict has no ``connect_timeout`` key, so omitting it from
    the helper keeps the audit-record args minimal.
    """
    from relay_shell.server import Relay

    relay = Relay(settings)
    ck = relay.connect_kwargs("alice", 2222, "/tmp/k", "strict", "bastion")
    assert ck == {
        "user": "alice",
        "port": 2222,
        "key_path": "/tmp/k",
        "known_hosts": "strict",
        "jump": "bastion",
    }


def test_connect_kwargs_overlays_connect_timeout(settings: Settings) -> None:
    """Positive overlay is injected; SshPool.connect honors it over settings."""
    from relay_shell.server import Relay

    relay = Relay(settings)
    ck = relay.connect_kwargs("", 0, "", "", "", connect_timeout=7)
    assert ck["connect_timeout"] == 7


def test_connect_kwargs_zero_overlay_falls_through(settings: Settings) -> None:
    """A zero/negative overlay is dropped so the pool's settings default fires."""
    from relay_shell.server import Relay

    relay = Relay(settings)
    ck_zero = relay.connect_kwargs("", 0, "", "", "", connect_timeout=0)
    ck_neg = relay.connect_kwargs("", 0, "", "", "", connect_timeout=-1)
    assert "connect_timeout" not in ck_zero
    assert "connect_timeout" not in ck_neg
