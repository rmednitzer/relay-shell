"""Small helpers shared by several test modules (importable as ``helpers``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def text(content: object) -> str:
    """Concatenate the text blocks of an MCP ``call_tool(...).content`` list."""
    return "".join(b.text for b in content if getattr(b, "type", "") == "text")  # type: ignore[attr-defined]


def audit_lines(path: Path) -> list[dict[str, Any]]:
    """Parsed audit records at ``path`` ([] when the file does not exist yet)."""
    if not path.is_file():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
