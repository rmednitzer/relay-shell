from __future__ import annotations

import re
from pathlib import Path

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
    "ssh_fanout",
    "ssh_keyscan",
    "ssh_hosts",
    "server_info",
    "audit_tail",
}

_REPO_ROOT = Path(__file__).resolve().parents[1]


async def test_all_tools_registered(settings: Settings) -> None:
    mcp = build_server(settings)
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == _EXPECTED
    assert len(names) == 21


async def test_every_tool_has_description(settings: Settings) -> None:
    mcp = build_server(settings)
    for tool in await mcp.list_tools():
        assert tool.description and len(tool.description) > 10


def _extract_tools_from_docs() -> set[str]:
    r"""Return the set of tool names declared by ``docs/tools.md``.

    The tool reference uses ``### `name``` headers for each tool, with
    merged headers like ``### `a` / `b``` when two tools share a
    description. Pick every backticked identifier under such a header
    inside the body sections (skip the resources/errors prose).
    """
    text = (_REPO_ROOT / "docs" / "tools.md").read_text(encoding="utf-8")
    # The Sessions table doesn't use H3 headers — it lists tools in a
    # markdown table. Capture both shapes.
    h3_section = re.compile(r"^### (.+)$", re.MULTILINE)
    found: set[str] = set()
    for hdr in h3_section.findall(text):
        for name in re.findall(r"`([a-z][a-z0-9_]*)`", hdr):
            found.add(name)
    # The Sessions section uses a single table; the first column is the
    # tool name in backticks.
    sessions_block = re.search(r"## Sessions[^\n]*\n.*?\n(?=## )", text, flags=re.DOTALL)
    if sessions_block:
        for row in sessions_block.group(0).splitlines():
            m = re.match(r"\|\s*`([a-z][a-z0-9_]*)`", row)
            if m:
                found.add(m.group(1))
    return found


def _extract_tools_from_readme() -> set[str]:
    """Tools mentioned by the README capability tables.

    The README lists every tool in markdown tables under "### Local
    shell", "### SSH", "### Sessions", and "### Diagnostics". Each
    relevant row starts with ``| `name` | ...``. Combined cells like
    ``| `a` / `b` | ...`` are flattened by picking every backticked
    identifier in the first cell.
    """
    text = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    found: set[str] = set()
    for line in text.splitlines():
        # Only consider rows whose second pipe-cell starts with a
        # backticked identifier — skips the header/divider rows.
        m = re.match(r"\|\s*([^|]+?)\s*\|", line)
        if not m:
            continue
        cell = m.group(1)
        # Skip table separator rows.
        if set(cell) <= set("- :"):
            continue
        for name in re.findall(r"`([a-z][a-z0-9_]*)`", cell):
            if name in _EXPECTED:
                found.add(name)
    return found


def _extract_tools_from_instructions() -> set[str]:
    """Tool names mentioned in the ``_INSTRUCTIONS`` server hint string."""
    from relay_shell import server as srv

    text = srv._INSTRUCTIONS
    return {name for name in re.findall(r"\b([a-z][a-z0-9_]*)\b", text) if name in _EXPECTED}


def test_docs_tools_md_matches_registered_set() -> None:
    """``docs/tools.md`` lists exactly the registered tool set.

    Drift here means a tool exists in code but has no documentation
    (or vice versa). The contract for adding a tool documented in
    AGENTS.md §6 and the runbook §6.1 includes this file; the check
    is here so a missed update fails a PR rather than ships silently.
    """
    docs_tools = _extract_tools_from_docs()
    assert docs_tools == _EXPECTED, (
        f"docs/tools.md drift: only-in-docs={docs_tools - _EXPECTED}, "
        f"only-in-registered={_EXPECTED - docs_tools}"
    )


def test_readme_capability_tables_match_registered_set() -> None:
    """README capability tables list exactly the registered tool set."""
    readme_tools = _extract_tools_from_readme()
    assert readme_tools == _EXPECTED, (
        f"README drift: only-in-README={readme_tools - _EXPECTED}, "
        f"only-in-registered={_EXPECTED - readme_tools}"
    )


def test_server_instructions_mentions_every_tool() -> None:
    """The FastMCP ``instructions`` string lists every registered tool.

    Closes the C-004 drift gap: when a new tool is added, the hint
    string at the bottom of ``server.py`` must mention it so the
    client model can discover it from the protocol-level overview.
    """
    mentioned = _extract_tools_from_instructions()
    missing = _EXPECTED - mentioned
    assert not missing, f"_INSTRUCTIONS omits registered tools: {sorted(missing)}"
    extras = mentioned - _EXPECTED
    assert not extras, f"_INSTRUCTIONS mentions unknown tools: {sorted(extras)}"


def test_instructions_carry_tool_selection_guidance() -> None:
    """``_INSTRUCTIONS`` gives the client criteria for picking a tool, not just a list.

    Listing every tool (the C-004 guard above) is necessary but not
    sufficient: the selection cliff this guidance closes is one-shot exec vs a
    persistent PTY session, plus the fact that spawning and the ``session_*``
    tools are one workflow rather than alternatives. Assert those cues are
    present so a future trim of the hint string does not silently drop them.
    """
    from relay_shell import server as srv

    text = srv._INSTRUCTIONS.lower()
    assert "choosing a tool" in text
    assert "runs and exits" in text  # the one-shot criterion
    assert "tty" in text  # the interactive/PTY criterion
    assert "one workflow" in text  # spawn + session_* are not alternatives


async def test_mode_selection_tools_cross_reference(settings: Settings) -> None:
    """The exec/spawn tool descriptions disambiguate each other.

    FastMCP surfaces the whole docstring as the tool ``description``, so the
    "use this; for the other case use X" pointer rides on the tool itself. A
    model weighing a one-shot command against a persistent PTY should see the
    alternative named in either direction, locally and over SSH.
    """
    mcp = build_server(settings)
    desc = {t.name: (t.description or "") for t in await mcp.list_tools()}
    # Local: one-shot <-> PTY session cross-reference.
    assert "shell_spawn" in desc["shell_exec"]
    assert "shell_exec" in desc["shell_spawn"]
    # SSH: one-shot <-> PTY session cross-reference.
    assert "ssh_spawn" in desc["ssh_exec"]
    assert "ssh_exec" in desc["ssh_spawn"]
