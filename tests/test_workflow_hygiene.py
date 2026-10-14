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


def test_ci_runs_the_caddy_routing_tests_and_the_privileged_seccomp_tests() -> None:
    """A14-D10 / A14-T1: tests that auto-skip locally must actually run somewhere."""
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert "CADDY_BINARY=" in text and "caddy/v2/cmd/caddy@v" in text
    assert "-m seccomp" in text and "sudo -E" in text


def test_codeql_also_scans_the_workflows_without_renaming_the_python_check() -> None:
    doc = yaml.safe_load((WORKFLOWS / "codeql.yml").read_text(encoding="utf-8"))
    jobs = doc["jobs"]
    assert jobs["analyze"]["name"] == "Analyze (python)"  # required-check name is unchanged
    steps = jobs["analyze-actions"]["steps"]
    init = next(s for s in steps if str(s.get("uses", "")).startswith("github/codeql-action/init@"))
    assert init["with"]["languages"] == "actions"


def test_gitleaks_allowlist_is_scoped_per_rule() -> None:
    import tomllib

    config = tomllib.loads((WORKFLOWS.parent.parent / ".gitleaks.toml").read_text("utf-8"))
    assert "allowlist" not in config, "a global allowlist hides every rule in those paths"
    for entry in config["allowlists"]:
        assert entry.get("targetRules"), "each allowlist names the rules it applies to"
        assert entry.get("paths")
