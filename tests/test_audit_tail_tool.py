"""Wiring tests for the ``audit_tail`` tool (B-003).

These exercise the tool through the FastMCP instance so the registration,
tier classification, output budget, and audit-record shape are all
covered together. The unit tests for :func:`AuditLogger.tail` itself
live in ``tests/test_audit.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from relay_shell.config import Settings
from relay_shell.policy import Tier, classify
from relay_shell.server import build_server


def _audit_lines(path: Path) -> list[dict[str, object]]:
    text = path.read_text(encoding="utf-8")
    return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


async def test_audit_tail_returns_existing_records(settings: Settings) -> None:
    mcp = build_server(settings)
    # Seed: a couple of real tool calls populate the audit log.
    await mcp.call_tool("server_info", {})
    await mcp.call_tool("server_info", {})

    content, _ = await mcp.call_tool("audit_tail", {"lines": 5})
    text = "".join(b.text for b in content if getattr(b, "type", "") == "text")
    # tail() output is JSONL; each line should parse and have the
    # required audit-record keys.
    records = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    assert len(records) >= 2  # at least the two server_info calls
    for rec in records:
        assert set(rec) >= {"ts", "tool", "tier", "denied", "args", "output_sha256"}


async def test_audit_tail_classified_tier_zero() -> None:
    # Belt-and-braces: even if the wrapper omits classification, the
    # tool registration must classify the tool as read-only.
    assert classify("audit_tail") is Tier.READ_ONLY


async def test_audit_tail_clamps_lines_argument(settings: Settings) -> None:
    mcp = build_server(settings)
    # An out-of-bound argument must not crash; the wrapper clamps to
    # [1, 1000].
    content, _ = await mcp.call_tool("audit_tail", {"lines": 999999})
    assert content  # tool returned bounded output, not an error string
    # The audit record for this call must show the *clamped* value, not
    # the raw input.
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["tool"] == "audit_tail"
    assert last["args"]["lines"] == 1000
    # And: zero / negative inputs collapse to 1.
    content2, _ = await mcp.call_tool("audit_tail", {"lines": 0})
    assert content2
    last2 = _audit_lines(Path(settings.audit_path))[-1]
    assert last2["args"]["lines"] == 1


async def test_audit_tail_empty_on_fresh_log(settings: Settings) -> None:
    mcp = build_server(settings)
    # No tool has been called yet (build_server itself does not call
    # tools), so the audit file exists but contains zero records.
    content, _ = await mcp.call_tool("audit_tail", {"lines": 50})
    text = "".join(b.text for b in content if getattr(b, "type", "") == "text")
    # The tool's OWN call lands in the audit too, but it lands AFTER the
    # tail() read (the audit.record() call happens after work() returns).
    # So the returned text is empty.
    assert text == ""
    # Confirm by re-reading: now exactly one record exists.
    assert len(_audit_lines(Path(settings.audit_path))) == 1


async def test_audit_tail_does_not_leak_output_body(settings: Settings) -> None:
    # The audit log never stores output bodies, only hashes. audit_tail
    # returns the log verbatim, so this is a structural invariant the
    # tool wrapper must preserve.
    #
    # Use the same `echo $((21+21))-only` trick as test_stdio_e2e: the
    # OUTPUT string ("body-42-only") is computed by the shell and never
    # appears in the audit-logged `args.command` field. Anything that
    # surfaces "body-42-only" in audit_tail output is a real body leak.
    mcp = build_server(settings)
    await mcp.call_tool("shell_exec", {"command": "echo body-$((21 + 21))-only"})
    content, _ = await mcp.call_tool("audit_tail", {"lines": 10})
    text = "".join(b.text for b in content if getattr(b, "type", "") == "text")
    assert "body-42-only" not in text


async def test_audit_tail_args_redacted_in_its_own_record(settings: Settings) -> None:
    # audit_tail logs `args={"lines": N}`. N is an int, so redaction is
    # a no-op; this test pins that the wrapper writes the audit args we
    # expect rather than something fuzzy that future code might read.
    mcp = build_server(settings)
    await mcp.call_tool("audit_tail", {"lines": 7})
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["tool"] == "audit_tail"
    assert last["args"] == {"lines": 7}
