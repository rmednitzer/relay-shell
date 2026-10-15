"""End-to-end coverage tests for every tool wrapper in `server.py`.

Most wrappers in `server.py` are otherwise exercised only by the stdio e2e
test (a subprocess), so unit coverage misses their bodies. This module calls
each tool through `mcp.call_tool()` with arguments that yield either valid
output or a structured error string, which verifies the audit, policy and
truncate path for every tool.

Deep semantics are covered by dedicated modules (`test_shell.py`,
`test_ssh_integration.py`, `test_ssh_keyscan_tool.py`, etc.); this module is
for breadth across the wrapper layer.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from helpers import text as _text
from relay_shell.config import Settings
from relay_shell.server import build_server

# --- local shell wrappers ---------------------------------------------


async def test_shell_exec_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (await mcp.call_tool("shell_exec", {"command": "echo hello"})).content
    out = _text(content)
    assert "hello" in out
    assert "[exit 0]" in out


async def test_shell_script_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (await mcp.call_tool("shell_script", {"script": "echo first; echo second"})).content
    out = _text(content)
    assert "first" in out and "second" in out


# --- boundary-contract tests: env_json reaches policy + audit (F-1) ---
#
# F-1: if shell_script and shell_spawn built policy_text from the script/command
# alone, a RELAY_SHELL_POLICY_DENY pattern matching only env content
# (LD_PRELOAD, PATH=, ...) would not fire and the audit record would lose the
# env. env_json must reach both the admission probe and the audit args, as it
# does for shell_exec.


async def test_shell_script_env_json_in_policy_text(tmp_path: Path) -> None:
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"LD_PRELOAD",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "shell_script",
            {"script": "echo hello", "env_json": '{"LD_PRELOAD": "/tmp/x.so"}'},
        )
    ).content
    out = _text(content)
    assert "DENIED" in out, (
        f"shell_script env_json must reach policy_text; got {out!r}. "
        "Pre-fix policy_text was script only, so a deny pattern matching "
        "only env content didn't fire."
    )


async def test_shell_script_env_json_in_audit_args(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    settings = Settings(
        transport="stdio",
        audit_path=str(path),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )
    mcp = build_server(settings)
    await mcp.call_tool(
        "shell_script",
        {"script": "echo ok", "env_json": '{"MY_VAR": "value"}'},
    )
    rec = json.loads(path.read_text(encoding="utf-8").strip())
    assert "env_json" in rec["args"], (
        f"shell_script must record env_json in audit args; got {rec['args']!r}"
    )
    # cwd is recorded (default "") alongside env_json, as for shell_exec.
    assert "cwd" in rec["args"]


async def test_shell_spawn_env_json_in_policy_text(tmp_path: Path) -> None:
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"LD_PRELOAD",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "shell_spawn",
            {"command": "/bin/sh", "env_json": '{"LD_PRELOAD": "/tmp/x.so"}'},
        )
    ).content
    out = _text(content)
    assert "DENIED" in out, (
        f"shell_spawn env_json must reach policy_text; got {out!r}. "
        "Pre-fix policy_text was command only."
    )


async def test_shell_spawn_env_json_in_audit_args(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    settings = Settings(
        transport="stdio",
        audit_path=str(path),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "shell_spawn",
            {"command": "/bin/sh", "env_json": '{"MY_VAR": "value"}'},
        )
    ).content
    # Best-effort cleanup so no live PTY leaks into other tests.
    sid_text = _text(content)
    if "session " in sid_text:
        sid = sid_text.split("session ", 1)[1].split()[0]
        await mcp.call_tool("session_kill", {"session_id": sid})

    rec = json.loads(path.read_text(encoding="utf-8").strip().splitlines()[0])
    assert "env_json" in rec["args"], (
        f"shell_spawn must record env_json in audit args; got {rec['args']!r}"
    )
    assert "cwd" in rec["args"]


# --- session lifecycle (covers shell_spawn + session_*) ---------------


async def test_session_lifecycle_covers_session_wrappers(settings: Settings) -> None:
    mcp = build_server(settings)

    content = (await mcp.call_tool("shell_spawn", {"command": "/bin/sh"})).content
    spawn_out = _text(content)
    # Body format: "[session <id> started] ..."
    assert "started" in spawn_out
    sid = spawn_out.split("session ", 1)[1].split()[0]
    try:
        content = (await mcp.call_tool("session_list", {})).content
        assert sid in _text(content)

        content = (
            await mcp.call_tool("session_send", {"session_id": sid, "data": "echo hi-$((20+22))\n"})
        ).content
        assert _text(content) == f"sent 20 bytes to {sid}"

        # The shell computes 20+22.
        recv_out = ""
        for _ in range(10):
            content = (
                await mcp.call_tool("session_recv", {"session_id": sid, "timeout": 0.5})
            ).content
            recv_out += _text(content)
            if "hi-42" in recv_out:
                break
        assert "hi-42" in recv_out

        content = (
            await mcp.call_tool("session_resize", {"session_id": sid, "cols": 80, "rows": 24})
        ).content
        assert _text(content) == f"resized {sid} to 80x24"
    finally:
        content = (await mcp.call_tool("session_kill", {"session_id": sid})).content
        assert _text(content) == f"killed and closed {sid}"


async def test_session_recv_unknown_id_surfaces_error(settings: Settings) -> None:
    # Unknown ids must surface a structured error, not an exception.
    mcp = build_server(settings)
    content = (
        await mcp.call_tool("session_recv", {"session_id": "does-not-exist", "timeout": 0})
    ).content
    assert _text(content) == "[ERROR: SessionError: unknown session: does-not-exist]"


async def test_session_kill_unknown_id_surfaces_error(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (await mcp.call_tool("session_kill", {"session_id": "does-not-exist"})).content
    assert _text(content) == "[ERROR: SessionError: unknown session: does-not-exist]"


async def test_session_resize_unknown_id_surfaces_error(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "session_resize", {"session_id": "does-not-exist", "cols": 80, "rows": 24}
        )
    ).content
    assert _text(content) == "[ERROR: SessionError: unknown session: does-not-exist]"


async def test_session_send_unknown_id_surfaces_error(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool("session_send", {"session_id": "does-not-exist", "data": "x"})
    ).content
    assert _text(content) == "[ERROR: SessionError: unknown session: does-not-exist]"


async def test_session_list_empty(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (await mcp.call_tool("session_list", {})).content
    assert _text(content) == "[]"


# --- ssh wrappers: error-path coverage --------------------------------
#
# The fixture has ssh_known_hosts="ignore" and an empty inventory, so an ssh_*
# call against an unresolvable host takes the wrapper's exception-handling
# branch. Deep behaviour is covered by tests/test_ssh_integration.py.


async def test_ssh_exec_unreachable_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_exec",
            {"host": "no-such-host-123.invalid", "command": "true", "timeout": 1},
        )
    ).content
    assert _text(content).startswith("[ERROR: ")


async def test_ssh_spawn_unreachable_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_spawn",
            {"host": "no-such-host-123.invalid"},
        )
    ).content
    assert _text(content).startswith("[ERROR: ")


async def test_ssh_upload_unreachable_wrapper(settings: Settings, tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("hi")
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_upload",
            {
                "host": "no-such-host-123.invalid",
                "local_path": str(src),
                "remote_path": "/tmp/dst.txt",
                "timeout": 1,
            },
        )
    ).content
    assert _text(content).startswith("[ERROR: ")


async def test_ssh_download_unreachable_wrapper(settings: Settings, tmp_path: Path) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_download",
            {
                "host": "no-such-host-123.invalid",
                "remote_path": "/tmp/whatever",
                "local_path": str(tmp_path / "dst.txt"),
                "timeout": 1,
            },
        )
    ).content
    assert _text(content).startswith("[ERROR: ")
    assert not (tmp_path / "dst.txt").exists()


async def test_ssh_forward_unreachable_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_forward",
            {
                "host": "no-such-host-123.invalid",
                "spec": "L:18080:example.org:80",
            },
        )
    ).content
    # A well-formed spec: the failure must come from dialling the host.
    assert _text(content).startswith("[ERROR: ")
    assert "invalid L forward spec" not in _text(content)


async def test_ssh_forward_list_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (await mcp.call_tool("ssh_forward_list", {})).content
    assert _text(content) == "[]"


async def test_ssh_forward_close_unknown_id_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool("ssh_forward_close", {"forward_id": "fwd-does-not-exist"})
    ).content
    assert _text(content) == "[ERROR: unknown forward: fwd-does-not-exist]"


async def test_ssh_check_against_inventory_wrapper(settings: Settings) -> None:
    # Empty inventory and empty hosts: the "no hosts" short-circuit.
    mcp = build_server(settings)
    content = (await mcp.call_tool("ssh_check", {})).content
    assert _text(content) == "[no hosts configured; pass hosts= or add an inventory]"


async def test_ssh_check_with_explicit_hosts_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool("ssh_check", {"hosts": "no-such-host-123.invalid", "timeout": 1})
    ).content
    out = _text(content)
    assert "UNREACHABLE" in out or "no-such-host" in out


async def test_ssh_check_bounds_per_host_output(settings: Settings) -> None:
    # PERF-4: ssh_check is Tier 0 (permitted even in `readonly` mode) and its
    # `hosts` are caller-chosen, so the probe's remote exec must bound buffered
    # output like every other SSH tool; otherwise a malicious or compromised sshd
    # could stream unbounded data back. Regression for a call that omitted
    # max_output_bytes (unlike ssh_exec/ssh_fanout).
    from relay_shell.server import _SSH_CHECK_PER_HOST_OUTPUT_CAP
    from relay_shell.sshpool import SshPool

    captured: dict[str, object] = {}
    original = SshPool.run

    async def spy_run(self: SshPool, target: str, command: str, **kwargs: object) -> object:
        captured.update(kwargs)
        return await original(self, target, command, **kwargs)

    mcp = build_server(settings)
    with patch.object(SshPool, "run", spy_run):
        await mcp.call_tool("ssh_check", {"hosts": "no-such-host-123.invalid", "timeout": 1})

    assert captured.get("max_output_bytes") == _SSH_CHECK_PER_HOST_OUTPUT_CAP


async def test_ssh_hosts_wrapper(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (await mcp.call_tool("ssh_hosts", {})).content
    assert _text(content) == "[]"


# --- server_info gets a direct unit test (closes T-002) --------------


async def test_server_info_reports_documented_fields(settings: Settings) -> None:
    # T-002 from runbook section 5.3: a direct check that every documented field
    # is present catches silent removals.
    mcp = build_server(settings)
    content = (await mcp.call_tool("server_info", {})).content
    info = json.loads(_text(content))
    # Top-level fields per docs/tools.md.
    for key in ("name", "version", "transport", "policy_mode", "runtime", "limits", "audit", "ssh"):
        assert key in info, f"server_info missing top-level key: {key}"
    assert info["version"]
    assert "path" in info["audit"]
    assert "degraded" in info["audit"]
    assert "format" in info["audit"]
    assert "chain" in info["audit"]
    for limit in (
        "default_timeout",
        "max_timeout",
        "max_output",
        "max_output_hard",
        "max_sessions",
    ):
        assert limit in info["limits"], f"server_info.limits missing {limit}"
    # The ssh substructure reports the connection-pool knobs so operators can diff
    # the live posture against their env file.
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
    """Without an overlay, ``connect_timeout`` is omitted.

    SshPool.connect falls back to settings.ssh_connect_timeout when the dict has
    no such key, and omitting it keeps the audit-record args minimal.
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
    """A positive overlay is injected and SshPool.connect honors it over settings."""
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


# --- policy_text builder contract (runbook R-002) -----------------------
#
# One builder per tool with a non-empty policy surface; each must include every
# byte the executor will see. Exact output (not substring presence) also pins
# the joining scheme, so a refactor cannot drop a part or fuse two parts into an
# unmatchable line.


def test_policy_text_builders_include_every_executor_visible_part() -> None:
    from relay_shell import server as srv

    assert srv._policy_text_shell_exec("CMD", "IN", "ENV") == "CMD\nIN\nENV"
    assert srv._policy_text_shell_exec("CMD", "", "") == "CMD"
    assert srv._policy_text_shell_script("BODY", "ENV") == "BODY\nENV"
    assert srv._policy_text_shell_script("BODY", "") == "BODY"
    assert srv._policy_text_shell_spawn("CMD", "ENV") == "CMD\nENV"
    # F2: the SSH command tools fold the destination host into the probe so
    # RELAY_SHELL_POLICY_DENY can gate the *target*, not just the command. The
    # command stays first (tier tokens unchanged); the host follows on its own
    # line. A plain hostname adds no canonical-IP suffix.
    assert srv._policy_text_ssh_exec("host1", "CMD") == "CMD\nhost1"
    assert srv._policy_text_ssh_spawn("host1", "") == "\nhost1"  # login shell
    assert srv._policy_text_ssh_fanout("h1, h2", "CMD") == "CMD\nh1, h2"
    assert srv._policy_text_ssh_check("h1 h2") == "h1 h2"
    assert srv._policy_text_session_send("DATA") == "DATA"
    up = srv._policy_text_ssh_upload("h", "/src", "/dst")
    assert up.startswith("upload ") and "/src" in up and "h:/dst" in up
    down = srv._policy_text_ssh_download("h", "/rem", "/loc")
    assert down.startswith("download ") and "h:/rem" in down and "/loc" in down
    fwd = srv._policy_text_ssh_forward("L:8080:db:5432")
    assert fwd.startswith("forward ") and "L:8080:db:5432" in fwd
    # SEC-1: the caller-chosen scan targets are the executor-visible part the deny
    # list must see.
    assert srv._policy_text_ssh_keyscan("h1, h2") == "h1, h2"


async def test_ssh_check_caps_host_count(settings: Settings) -> None:
    # SSH-2: a host list over the per-call cap errors before any connection
    # (as in ssh_fanout / ssh_keyscan).
    mcp = build_server(settings)
    hosts = " ".join(f"h{i}.invalid" for i in range(101))
    content = (await mcp.call_tool("ssh_check", {"hosts": hosts, "timeout": 1})).content
    out = _text(content)
    assert "exceeds the per-call cap" in out


async def test_ssh_tools_record_known_hosts_in_audit(settings: Settings) -> None:
    # SSH-1: the per-call host-key verification mode is recorded in the audit
    # args, so a per-call `ignore` downgrade is visible. An explicit value is
    # recorded verbatim; absent one, the effective server default is (here "ignore").
    mcp = build_server(settings)
    await mcp.call_tool(
        "ssh_exec",
        {
            "host": "no-such-host-123.invalid",
            "command": "true",
            "known_hosts": "strict",
            "timeout": 1,
        },
    )
    await mcp.call_tool(
        "ssh_exec", {"host": "no-such-host-123.invalid", "command": "true", "timeout": 1}
    )
    recs = [
        json.loads(ln)
        for ln in Path(settings.audit_path).read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    ssh_recs = [r for r in recs if r["tool"] == "ssh_exec"]
    assert ssh_recs[0]["args"]["known_hosts"] == "strict"
    assert ssh_recs[1]["args"]["known_hosts"] == "ignore"


# --- SSRF-2: IP-encoding normalization in the transfer/forward deny probes ---


def test_ssrf2_transfer_and_forward_probes_append_canonical_ip() -> None:
    from relay_shell.server import (
        _policy_text_ssh_download,
        _policy_text_ssh_forward,
        _policy_text_ssh_upload,
    )

    # Packed-decimal and hex spellings of 127.0.0.1 get the canonical form appended.
    assert "127.0.0.1" in _policy_text_ssh_upload("2130706433", "/tmp/x", "/srv/y")
    assert "127.0.0.1" in _policy_text_ssh_download("0x7f000001", "/srv/y", "/tmp/x")
    assert "127.0.0.1" in _policy_text_ssh_forward("L:8080:2130706433:80")
    # A hostname destination and a destination-less D: forward are unchanged.
    assert "[" not in _policy_text_ssh_upload("web01.example.com", "/a", "/b")
    assert _policy_text_ssh_forward("D:1080") == "forward D:1080"
    assert _policy_text_ssh_forward("garbage") == "forward garbage"


async def test_ssrf2_upload_deny_not_dodged_by_ip_encoding(tmp_path: Path) -> None:
    # An operator deny on the dotted-quad metadata IP must fire when the caller
    # spells the ssh_upload destination as a packed decimal (SSRF-2).
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"169\.254\.169\.254",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_upload",
            {"host": "2852039166", "local_path": "/tmp/x", "remote_path": "/srv/y"},
        )
    ).content
    assert "DENIED" in _text(content)
    recs = [
        json.loads(ln)
        for ln in Path(settings.audit_path).read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    assert [r for r in recs if r["tool"] == "ssh_upload"][-1]["denied"] is True


async def test_f2_deny_gates_host_for_rce_tools(tmp_path: Path) -> None:
    # F2 (2026-07-15): RELAY_SHELL_POLICY_DENY on a host must gate the tools that
    # grant remote execution, not only the transfer/scan tools. A denied host is
    # refused before any connection attempt, and an alternate IP spelling does not
    # dodge the deny (SSRF widening reaches the command tools too).
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"169\.254\.169\.254",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )
    mcp = build_server(settings)
    exec_out = _text(
        (
            await mcp.call_tool(
                "ssh_exec",
                {"host": "169.254.169.254", "command": "whoami", "timeout": 1},
            )
        ).content
    )
    assert "DENIED" in exec_out
    # The decimal spelling of the metadata IP is still gated.
    fanout_out = _text(
        (
            await mcp.call_tool(
                "ssh_fanout",
                {"command": "whoami", "hosts": "2852039166", "timeout": 1},
            )
        ).content
    )
    assert "DENIED" in fanout_out
    check_out = _text(
        (
            await mcp.call_tool(
                "ssh_check",
                {"hosts": "169.254.169.254", "timeout": 1},
            )
        ).content
    )
    assert "DENIED" in check_out
    # A non-denied host fails to connect instead, which is not a DENIED result.
    ok_out = _text(
        (
            await mcp.call_tool(
                "ssh_exec",
                {"host": "192.0.2.1", "command": "whoami", "timeout": 1},
            )
        ).content
    )
    assert "DENIED" not in ok_out


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("ssh_exec", {"command": "true"}),
        ("ssh_spawn", {}),
        ("ssh_upload", {"local_path": "/etc/hostname", "remote_path": "/tmp/x"}),
        ("ssh_download", {"remote_path": "/tmp/x", "local_path": "/tmp/y"}),
        ("ssh_forward", {"spec": "L:18080:example.org:80"}),
    ],
)
async def test_deny_list_sees_the_jump_host(
    tmp_path: Path, tool: str, args: dict[str, str]
) -> None:
    # The jump host is dialled first, so an operator deny on it (e.g. the cloud
    # metadata address) must fire even when the destination host looks harmless.
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"169\.254\.169\.254",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )
    mcp = build_server(settings)
    out = _text(
        (
            await mcp.call_tool(
                tool, {"host": "web1", "jump": "ops@169.254.169.254:22", "timeout": 1, **args}
            )
        ).content
    )
    assert "DENIED" in out
    # A harmless jump host is not refused.
    ok = _text(
        (
            await mcp.call_tool(
                tool, {"host": "web1.invalid", "jump": "bastion.invalid", "timeout": 1, **args}
            )
        ).content
    )
    assert "DENIED" not in ok


def test_jump_is_part_of_the_ssh_policy_probe() -> None:
    from relay_shell import server as srv

    # No jump: the probe text is unchanged.
    assert srv._policy_text_ssh_exec("h", "CMD") == "CMD\nh"
    assert srv._policy_text_ssh_exec("h", "CMD", "u@j:22") == "CMD\nh\nu@j:22"
    # A hex-spelled jump IP also gets its canonical form appended.
    assert "169.254.169.254" in srv._policy_text_ssh_exec("h", "CMD", "0xa9fea9fe")


def test_canonicalization_work_is_bounded_for_huge_host_lists() -> None:
    # Hex-spelled tokens are canonicalized with quadratic list/substring scans;
    # the caps on host counts are enforced only after the policy probe is built.
    import time

    from relay_shell import server as srv

    hosts = " ".join(f"0x{i:08x}" for i in range(30000))
    t0 = time.perf_counter()
    srv._policy_text_ssh_fanout(hosts, "true")
    assert time.perf_counter() - t0 < 2.0
