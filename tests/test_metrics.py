"""Tests for `relay_shell.metrics` and the HTTP `/metrics` route.

Coverage:
  - Counter increment + label ordering / escaping.
  - Gauge registration + live-read semantics.
  - Render shape: HELP, TYPE, samples, trailing newline.
  - `Relay.run` ticks `relay_shell_tool_calls_total` with the right outcome
    label on the deny / ok / error paths (scraped via `/metrics`).
  - The `/metrics` route is HTTP-only and serves the renderer's output.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from relay_shell.config import Settings
from relay_shell.metrics import (
    ACTIVE_FORWARDS,
    ACTIVE_SESSIONS,
    AUDIT_DEGRADED,
    SECCOMP_NOTIFY_EVENTS_TOTAL,
    SECCOMP_NOTIFY_OVERFLOW_TOTAL,
    TOOL_CALLS_TOTAL,
    Metrics,
)
from relay_shell.server import build_server

# --- pure registry tests ----------------------------------------------------


def test_counter_increment_and_label_ordering() -> None:
    m = Metrics()
    m.inc_tool_call(tool="shell_exec", tier=2, mode="open", outcome="ok")
    m.inc_tool_call(tool="shell_exec", tier=2, mode="open", outcome="ok")
    m.inc_tool_call(tool="shell_exec", tier=3, mode="open", outcome="denied")
    text = m.render()
    assert f"# HELP {TOOL_CALLS_TOTAL}" in text
    assert f"# TYPE {TOOL_CALLS_TOTAL} counter" in text
    assert f'{TOOL_CALLS_TOTAL}{{mode="open",outcome="ok",tier="2",tool="shell_exec"}} 2' in text
    assert (
        f'{TOOL_CALLS_TOTAL}{{mode="open",outcome="denied",tier="3",tool="shell_exec"}} 1' in text
    )
    assert text.endswith("\n")


def test_label_value_escaping() -> None:
    m = Metrics()
    m.inc_tool_call(tool='quote"-tool', tier=0, mode="open", outcome="ok")
    text = m.render()
    assert 'tool="quote\\"-tool"' in text


def test_gauge_register_and_live_read() -> None:
    m = Metrics()
    state = {"value": 7.0}
    m.register_gauge(ACTIVE_SESSIONS, lambda: state["value"])
    assert f"{ACTIVE_SESSIONS} 7.0" in m.render()
    state["value"] = 12.0
    assert f"{ACTIVE_SESSIONS} 12.0" in m.render()


def test_gauge_provider_exception_is_swallowed() -> None:
    m = Metrics()

    def _boom() -> float:
        raise RuntimeError("source disappeared")

    m.register_gauge(ACTIVE_FORWARDS, _boom)
    text = m.render()
    # HELP/TYPE still emitted, but no sample line for the misbehaving metric.
    assert f"# HELP {ACTIVE_FORWARDS}" in text
    assert f"# TYPE {ACTIVE_FORWARDS} gauge" in text
    assert f"\n{ACTIVE_FORWARDS} " not in text


def test_register_gauge_rejects_unknown_or_counter_metric() -> None:
    m = Metrics()
    with pytest.raises(ValueError):
        m.register_gauge("does_not_exist", lambda: 0.0)
    with pytest.raises(ValueError):
        m.register_gauge(TOOL_CALLS_TOTAL, lambda: 0.0)


def test_render_emits_every_metric_block() -> None:
    m = Metrics()
    text = m.render()
    for name in (
        TOOL_CALLS_TOTAL,
        SECCOMP_NOTIFY_EVENTS_TOTAL,
        SECCOMP_NOTIFY_OVERFLOW_TOTAL,
        ACTIVE_SESSIONS,
        ACTIVE_FORWARDS,
        AUDIT_DEGRADED,
    ):
        assert f"# HELP {name}" in text
        assert f"# TYPE {name}" in text


def test_seccomp_counters_increment_and_render() -> None:
    m = Metrics()
    m.inc_seccomp_event(syscall="execve")
    m.inc_seccomp_event(syscall="execve")
    m.inc_seccomp_event(syscall="openat")
    m.inc_seccomp_overflow()
    text = m.render()
    assert f"# TYPE {SECCOMP_NOTIFY_EVENTS_TOTAL} counter" in text
    assert f'{SECCOMP_NOTIFY_EVENTS_TOTAL}{{syscall="execve"}} 2' in text
    assert f'{SECCOMP_NOTIFY_EVENTS_TOTAL}{{syscall="openat"}} 1' in text
    # The overflow counter is unlabelled.
    assert f"{SECCOMP_NOTIFY_OVERFLOW_TOTAL} 1" in text


# --- HTTP /metrics route + Relay integration --------------------------------


def _http_settings(tmp_path, policy_mode: str = "open") -> Settings:
    return Settings(
        transport="http",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode=policy_mode,
        ssh_known_hosts="ignore",
        ssh_connect_timeout=5,
        ssh_keepalive=0,
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory="",
        auth_state_dir=str(tmp_path / "oauth"),
    )


def test_metrics_route_present_only_on_http(settings: Settings) -> None:
    stdio_mcp = build_server(settings)
    stdio_routes = [r.path for r in stdio_mcp.streamable_http_app().routes if hasattr(r, "path")]
    assert "/metrics" not in stdio_routes

    http_cfg = settings.model_copy(update={"transport": "http"})
    http_mcp = build_server(http_cfg)
    http_routes = [r.path for r in http_mcp.streamable_http_app().routes if hasattr(r, "path")]
    assert "/metrics" in http_routes


def test_metrics_route_serves_exposition(tmp_path) -> None:
    mcp = build_server(_http_settings(tmp_path))
    with TestClient(mcp.streamable_http_app()) as client:
        resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Every metric block is announced even with no samples yet.
    for name in (TOOL_CALLS_TOTAL, ACTIVE_SESSIONS, ACTIVE_FORWARDS, AUDIT_DEGRADED):
        assert f"# HELP {name}" in body
    # Gauges read live: audit is not degraded so it samples as 0.0.
    assert f"{AUDIT_DEGRADED} 0.0" in body
    assert f"{ACTIVE_SESSIONS} 0.0" in body
    assert f"{ACTIVE_FORWARDS} 0.0" in body
    assert body.endswith("\n")


async def test_tool_call_ok_ticks_counter_via_route(tmp_path) -> None:
    mcp = build_server(_http_settings(tmp_path))
    await mcp.call_tool("shell_exec", {"command": "echo hello"})
    with TestClient(mcp.streamable_http_app()) as client:
        body = client.get("/metrics").text
    # `echo hello` has no tier-2/3 keyword; classify() returns REVERSIBLE.
    assert f'{TOOL_CALLS_TOTAL}{{mode="open",outcome="ok",tier="1",tool="shell_exec"}} 1' in body


async def test_tool_call_denied_ticks_counter_via_route(tmp_path) -> None:
    mcp = build_server(_http_settings(tmp_path, policy_mode="readonly"))
    await mcp.call_tool("shell_exec", {"command": "rm -rf /"})
    with TestClient(mcp.streamable_http_app()) as client:
        body = client.get("/metrics").text
    assert (
        f'{TOOL_CALLS_TOTAL}{{mode="readonly",outcome="denied",tier="3",tool="shell_exec"}} 1'
        in body
    )


async def test_tool_call_error_ticks_counter_via_route(tmp_path) -> None:
    mcp = build_server(_http_settings(tmp_path))
    # Unreachable host -> work() raises RelayError -> outcome=error.
    await mcp.call_tool(
        "ssh_exec",
        {"host": "no-such-host-123.invalid", "command": "true", "timeout": 1},
    )
    with TestClient(mcp.streamable_http_app()) as client:
        body = client.get("/metrics").text
    assert 'outcome="error"' in body
    assert 'tool="ssh_exec"' in body
