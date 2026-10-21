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


def test_ci_gate_uses_paginated_snapshots_and_the_tested_evaluator() -> None:
    text = (WORKFLOWS / "ci-gate.yml").read_text(encoding="utf-8")
    assert "--paginate --slurp" in text and "filter=all" in text
    assert "python3 scripts/check_ci_checks.py" in text
    assert "2) ;;" in text  # only the evaluator's explicit pending result is retried


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
    gate = (WORKFLOWS / "ci-gate.yml").read_text(encoding="utf-8")
    assert "Analyze (actions)" in gate and "Analyze (python) (python)" in gate


def test_gitleaks_allowlist_is_scoped_per_rule() -> None:
    import tomllib

    config = tomllib.loads((WORKFLOWS.parent.parent / ".gitleaks.toml").read_text("utf-8"))
    assert "allowlist" not in config, "a global allowlist hides every rule in those paths"
    for entry in config["allowlists"]:
        assert entry.get("targetRules"), "each allowlist names the rules it applies to"
        assert entry.get("paths")


def test_qualified_profiles_keep_special_coverage_and_aggregate_checks_reachable() -> None:
    ci = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())["jobs"]["check"]
    profiles = ci["strategy"]["matrix"]["include"]
    assert {(p["os"], p["python-version"]) for p in profiles} == {
        ("ubuntu-24.04", "3.12"),
        ("ubuntu-26.04", "3.14"),
    }
    assert ci["runs-on"] == "${{ matrix.os }}"
    minors = {p["python-version"] for p in profiles}
    for step in ci["steps"]:
        if step.get("name") in {
            "Install Caddy (edge routing tests)",
            "Test (seccomp-notify end to end, privileged)",
        }:
            assert any(step["if"] == f"matrix.python-version == '{minor}'" for minor in minors)
    gate = yaml.safe_load((WORKFLOWS / "ci-gate.yml").read_text())
    checks = gate["jobs"]["ci-success"]["env"]["REQUIRED_CHECKS"].splitlines()
    assert {c for c in checks if c.startswith("check (py")} == {
        f"check (py{minor})" for minor in minors
    }
    root = WORKFLOWS.parent.parent
    for kind in ("runtime", "development"):
        assert {p.name for p in (root / "requirements").glob(f"{kind}-py*.txt")} == {
            f"{kind}-py{minor}.txt" for minor in minors
        }


def test_installer_rehearsal_covers_both_hosts_with_distinct_artifacts() -> None:
    jobs = yaml.safe_load((WORKFLOWS / "release-rehearsal.yml").read_text())["jobs"]
    rehearse = jobs["rehearse"]
    assert set(rehearse["strategy"]["matrix"]["os"]) == {"ubuntu-24.04", "ubuntu-26.04"}
    assert rehearse["runs-on"] == "${{ matrix.os }}"
    for step in rehearse["steps"]:
        if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
            assert "${{ matrix.os }}" in step["with"]["name"]
    assert set(jobs["release-rehearsal"]["needs"]) == {"rehearse", "cross-version"}
