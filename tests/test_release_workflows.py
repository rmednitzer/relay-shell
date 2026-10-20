"""Drift guards for the release and SBOM workflows (A14-D7).

The release path signs provenance and publishes, so the job that installs third-party
packages must not hold the OIDC/write token, tooling must be hash-locked, and a
``workflow_dispatch`` run must not be trusted from a feature branch.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOWS = ROOT / ".github/workflows"
RELEASE = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
SBOM = yaml.safe_load((WORKFLOWS / "sbom.yml").read_text(encoding="utf-8"))
PIP_INSTALL = re.compile(r"\bpip install\b")


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return list(job.get("steps", []))


def _run_text(job: dict[str, Any]) -> str:
    return "\n".join(str(step.get("run", "")) for step in _steps(job))


def _pip_lines(job: dict[str, Any]) -> list[str]:
    lines = []
    for raw in _run_text(job).splitlines():
        # A continuation or comment line never starts a command.
        if PIP_INSTALL.search(raw) and not raw.lstrip().startswith("#"):
            lines.append(raw.strip())
    return lines


@pytest.mark.parametrize("workflow", [RELEASE, SBOM], ids=["release", "sbom"])
def test_every_pip_install_is_hash_locked_or_constrained(workflow: dict[str, Any]) -> None:
    found = 0
    for name, job in workflow["jobs"].items():
        for line in _pip_lines(job):
            found += 1
            assert "--upgrade pip" not in line, f"{name}: unpinned pip upgrade: {line}"
            local_project = "--no-deps" in line and (
                ('--no-build-isolation -e ".[dev]"' in line)
                or ("--no-index" in line and ".sbom-dist/*.whl" in line)
            )
            assert "--require-hashes" in line or "-c requirements.txt" in line or local_project, (
                f"{name}: pip install without hashes or constraints: {line}"
            )
    assert found, "expected pip installs in the release/SBOM workflows"


@pytest.mark.parametrize("workflow", [RELEASE, SBOM], ids=["release", "sbom"])
def test_jobs_with_oidc_or_write_tokens_install_nothing(workflow: dict[str, Any]) -> None:
    for name, job in workflow["jobs"].items():
        perms = job.get("permissions", {})
        privileged = perms.get("id-token") == "write" or perms.get("contents") == "write"
        if not privileged:
            continue
        assert not _pip_lines(job), f"{name} holds OIDC/write but installs packages"
        assert not any(
            str(step.get("uses", "")).startswith("actions/setup-python") for step in _steps(job)
        ), f"{name} holds OIDC/write but sets up Python"
        assert "python -m build" not in _run_text(job)


def test_release_build_job_has_no_oidc_or_write_permission() -> None:
    perms = RELEASE["jobs"]["build"]["permissions"]
    assert perms == {"contents": "read"}


def test_release_builds_without_fetching_an_unpinned_backend() -> None:
    build = RELEASE["jobs"]["build"]
    text = _run_text(build)
    assert "python -m build --no-isolation" in text
    assert "--no-build-isolation" in text  # the editable dev install too
    assert "requirements-build.txt" in text
    assert "cache" not in {k for step in _steps(build) for k in step.get("with", {})}


def test_release_attests_what_publish_uploads() -> None:
    jobs = RELEASE["jobs"]
    attest_uses = [str(s.get("uses", "")) for s in _steps(jobs["attest"])]
    assert any(u.startswith("actions/download-artifact@") for u in attest_uses)
    assert any(u.startswith("actions/attest-build-provenance@") for u in attest_uses)
    assert set(jobs["attest"]["needs"]) == {"verify", "build"}
    assert "attest" in jobs["publish"]["needs"]
    assert "attest-build-provenance" not in " ".join(
        str(s.get("uses", "")) for s in _steps(jobs["build"])
    )


@pytest.mark.parametrize(
    ("workflow", "job"), [(RELEASE, "verify"), (SBOM, "sbom")], ids=["release", "sbom"]
)
def test_dispatch_is_only_trusted_from_main(workflow: dict[str, Any], job: str) -> None:
    condition = str(workflow["jobs"][job].get("if", ""))
    assert "github.event_name == 'push'" in condition
    assert "github.ref == 'refs/heads/main'" in condition


def test_sbom_runtime_environment_excludes_dev_tools_and_the_sbom_tool() -> None:
    text = _run_text(SBOM["jobs"]["sbom"])
    assert "-c requirements.txt ." in text  # constraints, not a requirements install
    assert "-r requirements.txt" not in text
    assert ".sbom-tool/bin/cyclonedx-py environment" in text  # separate venv for the tool
    assert "requirements-sbom.txt" in text
    assert "requirements/runtime-py3.14.txt" in text
    assert "--no-index --no-deps .sbom-dist/*.whl" in text


def _lock(path: str) -> dict[str, str]:
    """name -> pinned version for a ``pip-compile --generate-hashes`` file; every pin hashed."""
    text = (ROOT / path).read_text(encoding="utf-8")
    pins: dict[str, str] = {}
    for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text):
        match = re.match(r"([A-Za-z0-9_.-]+)==(\S+)", block)
        if not match:
            continue
        assert "--hash=sha256:" in block, f"{path}: {match.group(1)} has no hash"
        pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pins


def test_tooling_locks_are_fully_hashed_and_agree_with_requirements() -> None:
    constraints = {
        m.group(1).lower().replace("_", "-"): m.group(2)
        for m in re.finditer(
            r"^([A-Za-z0-9_.-]+)==(\S+)$",
            (ROOT / "requirements.txt").read_text(encoding="utf-8"),
            re.M,
        )
    }
    build, sbom = _lock("requirements-build.txt"), _lock("requirements-sbom.txt")
    assert {"build", "twine", "hatchling", "editables"} <= set(build)
    assert "cyclonedx-bom" in sbom
    for name, lock in (("requirements-build.txt", build), ("requirements-sbom.txt", sbom)):
        for package, version in lock.items():
            if package in constraints:
                # `-c requirements.txt` is applied in the same environment as the build
                # tooling, so a disagreement would silently re-pin a hash-locked package.
                assert constraints[package] == version, f"{name}: {package} drifted"


def test_pip_audit_covers_the_release_tooling_locks() -> None:
    text = (WORKFLOWS / "pip-audit.yml").read_text(encoding="utf-8")
    assert "-r requirements-build.txt" in text and "-r requirements-sbom.txt" in text


def test_tooling_locks_come_from_the_workflow_revision_not_the_release_checkout() -> None:
    # A workflow_dispatch recovery of an older tag checks out a commit that predates the
    # lock files, so they are fetched by SHA from the commit the workflow runs at.
    for workflow, job, lock in (
        (RELEASE, "build", "requirements-build.txt"),
        (SBOM, "sbom", "requirements-sbom.txt"),
    ):
        text = _run_text(workflow["jobs"][job])
        assert f"contents/{lock}?ref=${{WORKFLOW_SHA}}" in text
        assert f'-r "$RUNNER_TEMP/{lock}"' in text
        assert f"-r {lock}" not in text


def test_sbom_pins_the_cyclonedx_spec_version() -> None:
    text = _run_text(SBOM["jobs"]["sbom"])
    for fmt in ("JSON", "XML"):
        block = text.split(f"--of {fmt}", 1)[1].split("--output-reproducible", 1)[0]
        assert "--sv 1.5" in block, f"{fmt} SBOM does not pin spec 1.5"
    assert 'data.get("specVersion") == "1.5"' in text


@pytest.mark.parametrize("minor", ["3.12", "3.13", "3.14"])
def test_complete_profiles_preserve_runtime_scope_and_direct_constraints(minor: str) -> None:
    runtime = _lock(f"requirements/runtime-py{minor}.txt")
    development = _lock(f"requirements/development-py{minor}.txt")
    assert {"mcp", "asyncssh", "pydantic", "uvicorn"} <= set(runtime)
    assert not {"pytest", "twine", "hatchling", "mypy", "pip-audit"} & set(runtime)
    assert {"pytest", "ruff", "mypy", "hatchling", "editables"} <= set(development)
    assert all(development[name] == version for name, version in runtime.items())
    constraints = dict(
        re.findall(r"^([A-Za-z0-9_.-]+)==([^\s]+)$", (ROOT / "requirements.txt").read_text(), re.M)
    )
    for name, version in constraints.items():
        normalized = name.lower().replace("_", "-")
        for profile in (runtime, development):
            if normalized in profile:
                assert profile[normalized] == version


def test_audit_tool_has_its_own_hashed_environment() -> None:
    assert {"pip", "pip-audit"} <= set(_lock("requirements-audit.txt"))
    text = (WORKFLOWS / "pip-audit.yml").read_text()
    assert ".audit-tool/bin/python -m pip install --only-binary=:all: --require-hashes" in text
    assert '.audit-tool/bin/pip-audit --path "$AUDIT_SITE_PACKAGES"' in text
    assert "--upgrade pip" not in text
