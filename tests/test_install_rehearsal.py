"""Guard the destructive disposable-VM rehearsal and its snapshot comparison."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "install_rehearsal", Path(__file__).resolve().parents[1] / "scripts/rehearse_install.py"
)
assert SPEC is not None and SPEC.loader is not None
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)


def test_rehearsal_refuses_ordinary_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(RuntimeError, match="disposable"):
        rehearsal.guard()


def test_rehearsal_refuses_existing_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setattr(rehearsal.os, "geteuid", lambda: 0)
    monkeypatch.setattr(rehearsal, "TARGETS", (tmp_path,))
    with pytest.raises(RuntimeError, match="pre-existing"):
        rehearsal.guard()


def test_snapshot_identity_includes_modes_content_and_symlinks(tmp_path: Path) -> None:
    file = tmp_path / "data"
    file.write_text("synthetic")
    file.chmod(0o644)
    link = tmp_path / "link"
    link.symlink_to("data")
    original = rehearsal.inventory(tmp_path)
    file.chmod(0o600)
    changed = rehearsal.inventory(tmp_path)
    assert original != changed
    file.write_text("changed")
    assert changed != rehearsal.inventory(tmp_path)
    assert original["link"][-1] == "link:data"
