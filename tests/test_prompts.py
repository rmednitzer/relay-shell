"""Tests for the MCP prompt exposed by `build_server`.

A prompt is reusable, client-pullable guidance. One is registered:

  - `operating_guide`   how to choose and drive relay-shell's tools

Like a resource read, a prompt fetch is audited (tier 0,
`tool="prompt:operating_guide"`) and does not flow through `Relay.run`.
`prompts/list` returns metadata only and must NOT audit; `prompts/get` renders
the body and audits the pull. The body is hashed, never written. See ADR 0008.
"""

from __future__ import annotations

import json
from pathlib import Path

from relay_shell.config import Settings
from relay_shell.server import build_server


def _audit_lines(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _prompt_blob(result) -> str:
    """Flatten a GetPromptResult to a single string for substring checks."""
    return json.dumps(result.model_dump(), default=str)


async def test_operating_guide_prompt_listed(settings: Settings) -> None:
    mcp = build_server(settings)
    prompts = {p.name: p for p in await mcp.list_prompts()}
    assert "operating_guide" in prompts
    # A non-empty description is what a client renders in a prompt picker.
    assert prompts["operating_guide"].description


async def test_operating_guide_prompt_renders_guidance(settings: Settings) -> None:
    # The selection cliff this guidance closes must actually be in the body:
    # one-shot exec vs a persistent PTY session, plus the spawn+session loop.
    mcp = build_server(settings)
    blob = _prompt_blob(await mcp.get_prompt("operating_guide"))
    assert "shell_exec" in blob and "shell_spawn" in blob
    assert "session_send" in blob and "session_recv" in blob
    assert "one-shot" in blob.lower() or "runs and exits" in blob.lower()


async def test_listing_prompt_does_not_audit(settings: Settings) -> None:
    # Discovery returns metadata only - it must not call the function, so no
    # `prompt:*` line appears until a real fetch. (The audit file itself is
    # created at build time, so check for the line, not the file.)
    mcp = build_server(settings)
    await mcp.list_prompts()
    lines = _audit_lines(Path(settings.audit_path))
    assert not [e for e in lines if e["tool"].startswith("prompt:")]


async def test_fetching_prompt_is_audited_tier_zero(settings: Settings) -> None:
    mcp = build_server(settings)
    await mcp.get_prompt("operating_guide")
    lines = _audit_lines(Path(settings.audit_path))
    matching = [e for e in lines if e["tool"] == "prompt:operating_guide"]
    assert len(matching) == 1
    assert matching[0]["tier"] == 0
    assert matching[0]["denied"] is False
    # Stable tool label, no user-controlled args interpolated.
    assert matching[0]["args"] == {}
    # Body is never written - only its hash/length, same as tools/resources.
    assert "output_sha256" in matching[0]
    assert "output_len" in matching[0]


async def test_prompt_body_not_leaked_into_audit(settings: Settings) -> None:
    # The guide text is hashed into the record, never written verbatim.
    mcp = build_server(settings)
    await mcp.get_prompt("operating_guide")
    raw = Path(settings.audit_path).read_text().lower()
    assert "operating guide" not in raw
