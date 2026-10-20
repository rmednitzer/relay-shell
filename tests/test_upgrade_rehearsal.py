"""Discriminating guards for the historical fixture and its scoped disposition."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = load("rehearse_install")
with patch.dict(sys.modules, {"rehearse_install": common}):
    upgrade = load("rehearse_upgrade")


def test_baseline_identity_and_both_dependency_hashes(tmp_path: Path) -> None:
    source = ROOT / "tests/fixtures/upgrade-v0.3"
    assert upgrade.manifest(source)["version"] == "0.3.0"
    for filename in ("runtime.in", "runtime.lock", "advisory-description.txt"):
        destination = tmp_path / filename.replace(".", "-")
        shutil.copytree(source, destination)
        path = destination / filename
        path.write_text(path.read_text() + "\n# changed\n")
        with pytest.raises(ValueError, match="changed without review"):
            upgrade.manifest(destination)
    destination = tmp_path / "bad-identity"
    shutil.copytree(source, destination)
    data = json.loads((destination / "baseline.json").read_text())
    data["tag"] = "v0.3.0\nignored"
    (destination / "baseline.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="identity"):
        upgrade.manifest(destination)


def test_stateless_precondition_is_a_boolean_literal(tmp_path: Path) -> None:
    path = tmp_path / "server.py"
    for value, accepted in [("True", True), ("False", False), ("'True'", False)]:
        path.write_text(
            f"def build_server():\n    fastmcp_kwargs: dict = {{'stateless_http': {value}}}\n"
        )
        if accepted:
            upgrade.require_stateless(path)
        else:
            with pytest.raises(ValueError, match="stateless"):
                upgrade.require_stateless(path)


def test_advisory_disposition_is_exact_and_requires_complete_audit(tmp_path: Path) -> None:
    (tmp_path / "runtime.lock").write_text("mcp==1.28.1\nother==1.0\n")
    report = tmp_path / "audit.json"
    description = "Not affected: stateless_http=True"
    (tmp_path / "advisory-description.txt").write_text(description)
    finding = {"id": "CVE-2026-59951", "description": description}
    data = {
        "fixes": [],
        "dependencies": [
            {"name": "mcp", "version": "1.28.1", "vulns": [finding]},
            {"name": "other", "version": "1.0", "vulns": []},
        ],
    }

    def check():
        report.write_text(json.dumps(data))
        return upgrade.audit_dispositions(report, tmp_path)

    assert check()[0]["advisory"] == "CVE-2026-59951"
    finding["id"] = "CVE-unknown-fixture"
    with pytest.raises(ValueError, match="new reviewed disposition"):
        check()
    finding["id"] = "CVE-2026-59951"
    finding["description"] = "Changed upstream applicability"
    with pytest.raises(ValueError, match="new reviewed disposition"):
        check()
    finding["description"] = "Previously Not affected with stateless_http=True, but now affected"
    with pytest.raises(ValueError, match="new reviewed disposition"):
        check()
    finding["description"] = description
    data["dependencies"][0]["vulns"] = []
    with pytest.raises(ValueError, match="retained reviewed advisory"):
        check()
    data["dependencies"][0]["vulns"] = [finding]
    data["dependencies"][0]["version"] = "1.28.2"
    with pytest.raises(ValueError):
        check()
    data["dependencies"][0]["version"] = "1.28.1"
    data["dependencies"].pop()
    with pytest.raises(ValueError, match="exact frozen"):
        check()
