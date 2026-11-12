"""Prevent release version drift between package metadata and entry-point docs."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_entry_points_match_package_version() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    readme = (ROOT / "README.md").read_text()
    overview = (ROOT / "docs/index.md").read_text()
    readme_version = re.search(r"^v([0-9]+\.[0-9]+\.[0-9]+) · Python", readme, re.MULTILINE)
    assert readme_version is not None, "README release banner missing"
    assert readme_version.group(1) == version
    release = re.search(
        r"Current release: \*\*\[v([^]]+)\]"
        r"\(https://github\.com/rmednitzer/relay-shell/releases/tag/v([^)]+)\)"
        r"\*\* \((\d{4}-\d{2}-\d{2})\)",
        overview,
    )
    assert release is not None, "Website release banner missing"
    assert release.group(1) == release.group(2) == version
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert f"## [{version}] - {release.group(3)}" in changelog
