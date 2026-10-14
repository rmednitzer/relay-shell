"""A14-D12: checkout steps do not persist the token, and the CI gate reports a missing check."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"


def _steps(doc: dict) -> list[dict]:
    steps: list[dict] = []
    for job in (doc.get("jobs") or {}).values():
        steps.extend(job.get("steps") or [])
    return steps


def test_every_checkout_drops_the_token() -> None:
    seen = 0
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for step in _steps(doc):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                seen += 1
                assert (step.get("with") or {}).get("persist-credentials") is False, (
                    f"{path.name}: checkout keeps the token in .git/config"
                )
    assert seen >= 8


def test_ci_gate_distinguishes_a_missing_check_from_a_pending_one() -> None:
    text = (WORKFLOWS / "ci-gate.yml").read_text(encoding="utf-8")
    # `.check_runs[0]` is null when GitHub has no run by that name; without `// empty`
    # the row was "\t" (non-empty) and the "(missing)" branch could never fire.
    assert "(.check_runs[0] // empty)" in text
    assert "(missing)" in text
