"""Regression coverage for the cross-workflow security merge gate."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_security_checks_are_required_by_the_aggregate() -> None:
    text = (ROOT / ".github/workflows/ci-gate.yml").read_text()
    block = re.search(r"REQUIRED_CHECKS: \|-\n((?:        [^\n]*\n)+)", text)
    assert block is not None
    required = {line.strip() for line in block[1].splitlines()}
    assert {
        "gitleaks (secret scan)",
        "pip-audit (CVE scan)",
        "dependency-review",
        "Analyze (python) (python)",
    } <= required
