"""An upgrade must remove old graph nodes, not merely satisfy new dependencies."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "reconcile_runtime", Path(__file__).resolve().parents[1] / "scripts/reconcile_runtime.py"
)
assert SPEC is not None and SPEC.loader is not None
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def test_target_inventory_rejects_legacy_extras_missing_and_wrong_versions(tmp_path: Path) -> None:
    lock, project = tmp_path / "runtime.txt", tmp_path / "pyproject.toml"
    lock.write_text("mcp==2.3.0\nTyping_Extensions==4.16.0\n")
    project.write_text('[project]\nname="relay-shell"\nversion="0.4.0"\n')
    expected = runtime.expected_inventory(lock, project)
    installed = dict(expected, pip="26.2.1")
    runtime.validate_inventory(expected, installed)
    for legacy in ("certifi", "httpcore", "httpx", "httpx-sse", "setuptools"):
        with pytest.raises(ValueError, match="complete target lock"):
            runtime.validate_inventory(expected, dict(installed, **{legacy: "1.0"}))
    installed.pop("mcp")
    with pytest.raises(ValueError):
        runtime.validate_inventory(expected, installed)
    installed["mcp"] = "1.28.1"
    with pytest.raises(ValueError):
        runtime.validate_inventory(expected, installed)
