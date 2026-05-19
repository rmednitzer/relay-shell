from __future__ import annotations

from relay_shell.config import Settings
from relay_shell.server import build_server

_EXPECTED = {
    "shell_exec",
    "shell_script",
    "shell_spawn",
    "ssh_exec",
    "ssh_spawn",
    "session_send",
    "session_recv",
    "session_resize",
    "session_kill",
    "session_list",
    "ssh_upload",
    "ssh_download",
    "ssh_forward",
    "ssh_forward_list",
    "ssh_forward_close",
    "ssh_check",
    "ssh_hosts",
    "server_info",
}


async def test_all_tools_registered(settings: Settings) -> None:
    mcp = build_server(settings)
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == _EXPECTED
    assert len(names) == 18


async def test_every_tool_has_description(settings: Settings) -> None:
    mcp = build_server(settings)
    for tool in await mcp.list_tools():
        assert tool.description and len(tool.description) > 10
