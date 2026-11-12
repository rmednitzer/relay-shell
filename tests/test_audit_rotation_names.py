"""Rotated segments must belong to the selected audit stream."""

import json
import os
from pathlib import Path

import pytest

from relay_shell.audit import AuditLogger, _latest_rotated_path


@pytest.mark.parametrize("suffix", [".1", ".2.gz", "-20261112", "-20261112.gz"])
def test_rotation_selection_ignores_other_stream(tmp_path: Path, suffix: str) -> None:
    target = tmp_path / "audit.jsonl"
    unrelated = tmp_path / ("other.jsonl" + suffix)
    unrelated.write_text("unrelated\n")
    assert _latest_rotated_path(target) is None
    rotated = tmp_path / (target.name + suffix)
    rotated.write_text("selected stream\n")
    os.utime(rotated, ns=(1, 1))
    os.utime(unrelated, ns=(2, 2))
    assert _latest_rotated_path(target) == rotated


def test_new_stream_does_not_resume_another_stream(tmp_path: Path) -> None:
    unrelated = tmp_path / "other.jsonl.1"
    other = AuditLogger(str(unrelated), chain=True)
    other.record(tool="fixture", args={}, output="", exit_code=0, tier=0)
    target = tmp_path / "audit.jsonl"
    log = AuditLogger(str(target), chain=True)
    log.record(tool="fixture", args={}, output="", exit_code=0, tier=0)
    first = json.loads(target.read_text())
    assert first["seq"] == 0
    assert first["prev"] == "0" * 64
