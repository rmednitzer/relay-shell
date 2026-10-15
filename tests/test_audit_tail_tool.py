"""Wiring tests for the ``audit_tail`` tool (B-003).

They go through the FastMCP instance, covering registration, tier
classification, output budget and audit-record shape together. Unit tests
for :func:`AuditLogger.tail` are in ``tests/test_audit.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from helpers import audit_lines as _audit_lines
from helpers import text as _text
from relay_shell.config import Settings
from relay_shell.policy import Tier, classify
from relay_shell.server import build_server


async def test_audit_tail_returns_existing_records(settings: Settings) -> None:
    mcp = build_server(settings)
    # Seed the audit log with real tool calls.
    await mcp.call_tool("server_info", {})
    await mcp.call_tool("server_info", {})

    content = (await mcp.call_tool("audit_tail", {"lines": 5})).content
    text = "".join(b.text for b in content if getattr(b, "type", "") == "text")
    records = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    assert len(records) >= 2  # at least the two server_info calls
    for rec in records:
        assert set(rec) >= {"ts", "tool", "tier", "denied", "args", "output_sha256"}


def test_audit_tail_classified_tier_zero() -> None:
    # Must classify as read-only even if the wrapper omits classification.
    # Synchronous on purpose: ruff RUF029 flags an async def without await.
    assert classify("audit_tail") is Tier.READ_ONLY


async def test_audit_tail_clamps_lines_argument(settings: Settings) -> None:
    mcp = build_server(settings)
    # An out-of-bound argument must not crash; the wrapper clamps to [1, 1000].
    content = (await mcp.call_tool("audit_tail", {"lines": 999999})).content
    assert content  # bounded output, not an error string
    # The audit record shows the clamped value, not the raw input.
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["tool"] == "audit_tail"
    assert last["args"]["lines"] == 1000
    # Zero and negative inputs collapse to 1.
    content2 = (await mcp.call_tool("audit_tail", {"lines": 0})).content
    assert content2
    last2 = _audit_lines(Path(settings.audit_path))[-1]
    assert last2["args"]["lines"] == 1


async def test_audit_tail_empty_on_fresh_log(settings: Settings) -> None:
    mcp = build_server(settings)
    # build_server calls no tools: the audit file exists with zero records.
    content = (await mcp.call_tool("audit_tail", {"lines": 50})).content
    text = "".join(b.text for b in content if getattr(b, "type", "") == "text")
    # The tool's own call is audited after the tail() read (record() runs
    # after work() returns), so the returned text is empty.
    assert text == ""
    assert len(_audit_lines(Path(settings.audit_path))) == 1


async def test_audit_tail_does_not_leak_output_body(settings: Settings) -> None:
    # The audit log stores output hashes, never bodies, and audit_tail returns
    # it verbatim. As in test_stdio_e2e, the shell computes "body-42-only", so
    # it never appears in the logged `args.command`; seeing it in audit_tail
    # output is a real body leak.
    mcp = build_server(settings)
    await mcp.call_tool("shell_exec", {"command": "echo body-$((21 + 21))-only"})
    content = (await mcp.call_tool("audit_tail", {"lines": 10})).content
    text = "".join(b.text for b in content if getattr(b, "type", "") == "text")
    assert "body-42-only" not in text


async def test_audit_tail_args_redacted_in_its_own_record(settings: Settings) -> None:
    # audit_tail logs `args={"lines": N}`; N is an int, so redaction is a
    # no-op. (AUD-1: an unfiltered call must still record exactly
    # {"lines": N}; the filter keys are additive, present only when set.)
    mcp = build_server(settings)
    await mcp.call_tool("audit_tail", {"lines": 7})
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["tool"] == "audit_tail"
    assert last["args"] == {"lines": 7}


# --- AUD-1: read-only triage filters (tool / tier / denied) ---------------


async def _seed_mixed(mcp: object) -> None:
    # A tier-1 ok call, a tier-3 call denied by `guarded`, and a tier-0 call.
    await mcp.call_tool("shell_exec", {"command": "echo ok"})  # type: ignore[attr-defined]
    await mcp.call_tool("shell_exec", {"command": "rm -rf /tmp/relay-nope"})  # type: ignore[attr-defined]
    await mcp.call_tool("server_info", {})  # type: ignore[attr-defined]


def _guarded(tmp_path: Path) -> Settings:
    return Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="guarded",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory="",
    )


async def test_audit_tail_filter_by_tool(tmp_path: Path) -> None:
    mcp = build_server(_guarded(tmp_path))
    await _seed_mixed(mcp)
    content = (await mcp.call_tool("audit_tail", {"lines": 50, "tool": "shell_exec"})).content
    recs = [json.loads(ln) for ln in _text(content).splitlines() if ln.strip()]
    assert recs and all(r["tool"] == "shell_exec" for r in recs)
    assert len(recs) == 2  # the ok call and the denied call


async def test_audit_tail_filter_by_denied(tmp_path: Path) -> None:
    mcp = build_server(_guarded(tmp_path))
    await _seed_mixed(mcp)
    content = (await mcp.call_tool("audit_tail", {"lines": 50, "denied": True})).content
    recs = [json.loads(ln) for ln in _text(content).splitlines() if ln.strip()]
    assert recs and all(r["denied"] is True for r in recs)
    assert all(r["tool"] == "shell_exec" for r in recs)  # only the Tier-3 rm is denied


async def test_audit_tail_filter_by_tier(tmp_path: Path) -> None:
    mcp = build_server(_guarded(tmp_path))
    await _seed_mixed(mcp)
    content = (await mcp.call_tool("audit_tail", {"lines": 50, "tier": 0})).content
    recs = [json.loads(ln) for ln in _text(content).splitlines() if ln.strip()]
    assert recs and all(r["tier"] == 0 for r in recs)  # server_info (+ prior audit_tail reads)


async def test_audit_tail_filters_recorded_only_when_set(tmp_path: Path) -> None:
    cfg = _guarded(tmp_path)
    mcp = build_server(cfg)
    await mcp.call_tool("audit_tail", {"lines": 5, "tool": "shell_exec", "denied": True})
    last = _audit_lines(Path(cfg.audit_path))[-1]
    assert last["args"] == {"lines": 5, "tool_filter": "shell_exec", "denied_filter": True}


async def test_audit_tail_no_match_returns_empty(tmp_path: Path) -> None:
    mcp = build_server(_guarded(tmp_path))
    await _seed_mixed(mcp)
    content = (await mcp.call_tool("audit_tail", {"lines": 50, "tool": "no_such_tool"})).content
    assert _text(content) == ""
