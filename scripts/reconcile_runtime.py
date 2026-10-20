"""Reconcile the dedicated service venv with its locked distribution inventory."""

from __future__ import annotations

import argparse
import importlib.metadata
import re
import subprocess
import sys
import tomllib
from pathlib import Path


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def expected_inventory(lock: Path, project: Path) -> dict[str, str]:
    expected = {
        normalize(name): version
        for name, version in re.findall(
            r"^([A-Za-z0-9_.-]+)==([^\s]+)", lock.read_text(), re.MULTILINE
        )
    }
    if not expected:
        raise ValueError("empty runtime lock")
    metadata = tomllib.loads(project.read_text())["project"]
    expected[normalize(metadata["name"])] = metadata["version"]
    return expected


def validate_inventory(expected: dict[str, str], installed: dict[str, str]) -> None:
    # pip is the sole bootstrap tool retained in this dedicated runtime venv.
    actual = {name: version for name, version in installed.items() if name != "pip"}
    if actual != expected:
        raise ValueError("installed runtime distributions differ from the complete target lock")


def inventory() -> dict[str, str]:
    result: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = normalize(distribution.metadata["Name"])
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", name) or name in result:
            raise ValueError("invalid or duplicate installed distribution")
        result[name] = distribution.version
    return result


def reconcile(lock: Path, project: Path, *, prune: bool) -> None:
    if sys.prefix == sys.base_prefix:
        raise ValueError("runtime reconciliation requires a dedicated virtual environment")
    expected = expected_inventory(lock, project)
    installed = inventory()
    extras = sorted(set(installed) - set(expected) - {"pip"})
    if extras and prune:
        subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "--yes", "--", *extras],
            check=True,
            timeout=120,
        )
        # Re-read metadata in a fresh process after uninstalling distributions.
        subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), str(lock), str(project)],
            check=True,
            timeout=30,
        )
        return
    validate_inventory(expected, installed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("project", type=Path)
    parser.add_argument("--prune", action="store_true")
    arguments = parser.parse_args()
    reconcile(arguments.lock, arguments.project, prune=arguments.prune)
