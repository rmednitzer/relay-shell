"""Exercise release/SBOM preparation and complete-environment recovery without publishing.

Run from a committed checkout with PyYAML available. Only disposable directories
are changed. The production workflow's named shell steps are executed verbatim;
tag admission and privileged signing/publishing are deliberately separate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], cwd: Path, env: dict[str, str]) -> None:
    subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=600)


def workflow_step(workflow: str, job: str, name: str, cwd: Path, env: dict[str, str]) -> None:
    definition = yaml.safe_load((cwd / ".github/workflows" / workflow).read_text())
    steps = [step for step in definition["jobs"][job]["steps"] if step.get("name") == name]
    if len(steps) != 1 or not isinstance(steps[0].get("run"), str):
        raise ValueError("rehearsal workflow step contract changed")
    command = steps[0]["run"]
    if "${{" in command:
        raise ValueError("unexpanded workflow expression in rehearsal step")
    run(["bash", "-euo", "pipefail", "-c", command], cwd, env)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): (
            "link:" + str(path.readlink()) if path.is_symlink() else "file:" + digest(path)
        )
        for path in root.rglob("*")
        if path.is_symlink() or path.is_file()
    }


def rehearse(python: str, output: Path) -> None:
    if output.exists():
        raise ValueError("output must be a new directory")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(prefix="relay-release-rehearsal-") as temporary:
        work = Path(temporary)
        checkout = work / "source"
        checkout.mkdir()
        archive = work / "source.tar"
        with archive.open("wb") as stream:
            subprocess.run(
                ["git", "archive", "--format=tar", source],
                cwd=ROOT,
                stdout=stream,
                check=True,
                timeout=30,
            )
        with tarfile.open(archive) as stream:
            stream.extractall(checkout, filter="data")
        version = tomllib.loads((checkout / "pyproject.toml").read_text())["project"]["version"]
        tooling = work / "workflow-locks"
        tooling.mkdir()
        for name in ("requirements-build.txt", "requirements-sbom.txt"):
            shutil.copy2(checkout / name, tooling / name)
        env = {
            **os.environ,
            "RUNNER_TEMP": str(tooling),
            "TAG_NAME": "v" + version,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        target_version = subprocess.check_output(
            [python, "-c", "import sys; print('.'.join(map(str,sys.version_info[:3])))"], text=True
        ).strip()
        if not target_version.startswith("3.14."):
            raise ValueError("release rehearsal requires the workflow's Python 3.14 profile")
        run([python, "-m", "venv", str(work / "release-env")], checkout, env)
        env["PATH"] = str(work / "release-env/bin") + os.pathsep + env["PATH"]
        for name in (
            "Install build tooling (hash-locked) and the package",
            "Build wheel + sdist",
            "Check distributions",
        ):
            workflow_step("release.yml", "build", name, checkout, env)
        workflow_step(
            "sbom.yml",
            "sbom",
            "Install runtime dependencies and the hash-locked SBOM tool",
            checkout,
            env,
        )
        workflow_step("sbom.yml", "sbom", "Generate CycloneDX SBOM", checkout, env)

        runtime = checkout / ".sbom-venv"
        snapshot = work / "saved-runtime"
        expected = inventory(runtime)
        shutil.copytree(runtime, snapshot, symlinks=True)
        executable = str(runtime / "bin/python")
        # Model an interrupted dependency replacement in an isolated installation.
        run([executable, "-m", "pip", "uninstall", "-y", "mcp"], checkout, env)
        broken = subprocess.run(
            [executable, "-m", "pip", "check"],
            cwd=checkout,
            env=env,
            capture_output=True,
            timeout=30,
        )
        if broken.returncode == 0:
            raise ValueError("damaged runtime unexpectedly passed dependency checks")
        damaged = work / "damaged-runtime"
        runtime.rename(damaged)
        # Restore at the original absolute path; venvs are not relocatable.
        snapshot.rename(runtime)
        if inventory(runtime) != expected:
            raise ValueError("complete runtime restoration changed file or symlink contents")
        run([executable, "-m", "pip", "check"], checkout, env)
        run([executable, "-c", "import relay_shell.server"], checkout, env)

        sbom_path = checkout / f"relay-shell-v{version}.cdx.json"
        sbom = json.loads(sbom_path.read_text())
        names = {item["name"].lower().replace("_", "-") for item in sbom["components"]}
        if not {"relay-shell", "mcp", "asyncssh"} <= names or names & {
            "pytest",
            "twine",
            "cyclonedx-bom",
        }:
            raise ValueError("SBOM runtime/tool separation failed")
        artifacts = list((checkout / "dist").iterdir())
        if len(artifacts) != 2 or sum(p.suffix == ".whl" for p in artifacts) != 1:
            raise ValueError("expected exactly one wheel and one source distribution")
        output.mkdir(parents=True)
        files = [*artifacts, sbom_path, checkout / f"relay-shell-v{version}.cdx.xml"]
        receipt = {
            "source_commit": source,
            "python": target_version,
            "artifacts": {p.name: digest(p) for p in files},
            "runtime_components": len(names),
            "restored_files": len(expected),
            "dependency_failure_detected": True,
            "complete_restore_identical": True,
            "restored_dependency_check": "passed",
            "restored_application_import": "passed",
            "scope": (
                "disposable package environments; no tag admission, signing, "
                "publication or service deployment"
            ),
        }
        for path in files:
            shutil.copy2(path, output / path.name)
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="python")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    rehearse(arguments.python, arguments.output.resolve())
