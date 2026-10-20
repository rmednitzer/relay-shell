"""Exercise the gate's real CLI with synthetic paginated API responses."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_ci_checks.py"


def check(check_id: int = 1, **overrides: object) -> dict:
    return {
        "id": check_id,
        "name": "required",
        "head_sha": "candidate",
        "app": {"id": 15368},
        "status": "completed",
        "conclusion": "success",
        **overrides,
    }


@pytest.mark.parametrize(
    ("pages", "status", "message"),
    [
        ([{"check_runs": []}, {"check_runs": [check()]}], 0, "passed"),
        ([{"check_runs": []}], 2, "missing"),
        ([{"check_runs": [check(app={"id": 42})]}], 2, "missing"),
        ([{"check_runs": [check(head_sha="old")]}], 2, "missing"),
        ([{"check_runs": [check(2, status="queued"), check(1)]}], 2, "queued"),
        ([{"check_runs": [check(2, conclusion="failure"), check(1)]}], 1, "failure"),
        ([{"check_runs": [check(1, conclusion="failure"), check(2)]}], 0, "passed"),
        ([{"check_runs": [check(conclusion="cancelled")]}], 1, "cancelled"),
        ([{"check_runs": [check(conclusion="skipped")]}], 1, "skipped"),
        ([{"check_runs": [check(conclusion="neutral")]}], 1, "neutral"),
        ([{"unexpected": []}], 1, "Invalid"),
    ],
)
def test_gate_reconciles_current_producer_revision_and_attempt(pages, status, message) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(pages),
        capture_output=True,
        text=True,
        env={**os.environ, "TARGET_SHA": "candidate", "REQUIRED_CHECKS": "required"},
        timeout=5,
    )
    assert result.returncode == status
    assert message in result.stdout + result.stderr


def test_invalid_json_cannot_become_a_pass() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input="not JSON",
        capture_output=True,
        text=True,
        env={**os.environ, "TARGET_SHA": "candidate", "REQUIRED_CHECKS": "required"},
        timeout=5,
    )
    assert result.returncode == 1
