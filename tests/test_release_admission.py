"""Execute the release workflow's admission scripts against synthetic signed Git history."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())


def command(name: str) -> str:
    return next(s["run"] for s in WORKFLOW["jobs"]["verify"]["steps"] if s.get("name") == name)


@pytest.mark.parametrize("tag", ["v0.4.0", "v0.4.0-rc.1", "v0.4.0+build.1"])
def test_release_tag_resolution_accepts_one_canonical_line(tmp_path: Path, tag: str) -> None:
    result = resolve(tmp_path, tag)
    assert result.returncode == 0
    assert (tmp_path / "outputs").read_text() == f"tag={tag}\n"


def resolve(tmp_path: Path, tag: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", command("Resolve tag from trigger")],
        env={
            **os.environ,
            "INPUT_TAG": tag,
            "REF": "refs/heads/main",
            "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        },
        capture_output=True,
        text=True,
        timeout=5,
    )


@pytest.mark.parametrize(
    "tag", ["main", "v0.4.0\nrelease_commit=bad", "v0.4.0-x\ny", "v0.4.0-../x"]
)
def test_release_tag_resolution_refuses_output_injection(tmp_path: Path, tag: str) -> None:
    assert resolve(tmp_path, tag).returncode != 0
    assert not (tmp_path / "outputs").exists()


@pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="OpenSSH required for real tag signatures"
)
@pytest.mark.parametrize(
    "case",
    ["trusted", "lightweight", "unsigned", "foreign-key", "outside-main", "checkout-mismatch"],
)
def test_signed_tag_admission_uses_protected_main_trust(tmp_path: Path, case: str) -> None:
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        "TAG": "v0.4.0",
    }
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=repo, env=env, stderr=subprocess.DEVNULL, text=True
        ).strip()

    key = tmp_path / "signing-key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    git("init", "-b", "main")
    git("config", "user.name", "Synthetic release fixture")
    git("config", "user.email", "release@example.invalid")
    git("config", "gpg.format", "ssh")
    git("config", "user.signingkey", str(key))
    (repo / "deploy").mkdir()
    (repo / "deploy/release-signing.pub").write_text(
        "release@example.invalid " + key.with_suffix(".pub").read_text()
    )
    git("add", ".")
    git("commit", "-m", "Synthetic protected baseline")
    upstream = tmp_path / "upstream.git"
    subprocess.run(["git", "init", "--bare", str(upstream)], check=True, capture_output=True)
    git("remote", "add", "origin", str(upstream))
    git("push", "origin", "main")
    if case == "outside-main":
        git("checkout", "-b", "unadmitted")
        (repo / "unadmitted").write_text("not on main")
        git("add", ".")
        git("commit", "-m", "Synthetic unadmitted change")
    if case == "foreign-key":
        foreign = tmp_path / "foreign-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(foreign)], check=True
        )
        git("config", "user.signingkey", str(foreign))
        # An attacker-controlled checkout cannot authorize its own tag signer.
        (repo / "deploy/release-signing.pub").write_text(
            "release@example.invalid " + foreign.with_suffix(".pub").read_text()
        )
    if case == "lightweight":
        git("tag", "v0.4.0")
    elif case == "unsigned":
        git("tag", "-a", "v0.4.0", "-m", "unsigned fixture")
    else:
        git("tag", "-s", "v0.4.0", "-m", "signed fixture")
    if case == "checkout-mismatch":
        (repo / "later").write_text("newer checkout than the signed tag")
        git("add", ".")
        git("commit", "-m", "Synthetic later checkout")
        git("push", "origin", "main")
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", command("Verify tag signature locally")],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert (result.returncode == 0) == (case == "trusted"), result.stdout + result.stderr
    if case == "trusted":
        assert (tmp_path / "outputs").read_text() == f"release_commit={git('rev-parse', 'HEAD')}\n"
    else:
        assert not (tmp_path / "outputs").exists()


@pytest.mark.parametrize(
    ("version", "tag", "accepted"),
    [
        ("0.4.0", "v0.4.0", True),
        ("0.4.0rc1", "v0.4.0-rc.1", True),
        ("0.4.0", "v0.4.1", False),
        ("0.0.1", "v0.0.2", False),
    ],
)
def test_sbom_admission_requires_matching_release_version(
    tmp_path: Path, version: str, tag: str, accepted: bool
) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/sbom.yml").read_text())
    step = next(
        s["run"]
        for s in workflow["jobs"]["sbom"]["steps"]
        if s.get("name") == "Generate CycloneDX SBOM"
    )
    script = step.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "specVersion": "1.5",
                "components": [
                    {"name": "mcp", "version": "2.3.0"},
                    {"name": "relay-shell", "version": version},
                ],
            }
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(sbom), tag], capture_output=True, text=True, timeout=5
    )
    assert (result.returncode == 0) == accepted
    if not accepted:
        assert "SBOM_RELEASE_IDENTITY_REFUSED" in result.stderr
