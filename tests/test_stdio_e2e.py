"""End-to-end: launch the server as a subprocess and speak MCP over stdio.

This exercises the real transport, the FastMCP wiring, the audited runner, and
an actual tool call - no mocks.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_stdio_initialize_list_and_call(tmp_path: Path) -> None:
    env = dict(os.environ)
    env.update(
        {
            "MCPX_TRANSPORT": "stdio",
            "MCPX_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
            "MCPX_POLICY_MODE": "open",
            "MCPX_SSH_CONFIG": str(tmp_path / "no_cfg"),
        }
    )
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcpx"], env=env)

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        listed = await session.list_tools()
        names = {t.name for t in listed.tools}
        assert "shell_exec" in names
        assert "ssh_exec" in names
        assert len(names) == 18

        info = await session.call_tool("server_info", {})
        info_text = "".join(
            block.text for block in info.content if getattr(block, "type", "") == "text"
        )
        assert '"name": "mcpx"' in info_text
        assert '"policy_mode": "open"' in info_text

        # The command (an argument) is deliberately audited; the OUTPUT body is
        # not - only its hash. Use a value that appears solely in the output.
        ran = await session.call_tool("shell_exec", {"command": "echo body-$((21 + 21))-only"})
        out = "".join(block.text for block in ran.content if getattr(block, "type", "") == "text")
        assert "body-42-only" in out
        assert "[exit 0]" in out

    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert '"tool": "server_info"' in audit
    assert '"tool": "shell_exec"' in audit
    assert '"output_sha256"' in audit
    # Output body must never be written - only the expanded result proves this.
    assert "body-42-only" not in audit
