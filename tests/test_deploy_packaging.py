"""A14-D15: wheel contents, installer backups and the metrics temp file."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

from relay_shell.verifier import DEFAULT_PAIRS

ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash")


def test_wheel_ships_exactly_the_verifier_templates() -> None:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    forced = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    expected = {
        f"deploy/{p.template_rel}": f"relay_shell/_deploy/{p.template_rel}" for p in DEFAULT_PAIRS
    }
    assert forced == expected
    for source in forced:
        assert (ROOT / source).is_file(), source


@pytest.mark.skipif(BASH is None, reason="bash is required")
def test_install_managed_keeps_a_copy_of_a_locally_modified_file(tmp_path: Path) -> None:
    text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    start = text.index("install_managed() {")
    end = text.index("\n}\n", start) + 3
    func = text[start:end]
    src = tmp_path / "template"
    dst = tmp_path / "etc" / "unit.conf"
    dst.parent.mkdir()
    src.write_text("shipped\n")
    backups = tmp_path / "backups"
    script = (
        'log() { echo "$*"; }\n'
        f'BACKUP_DIR="{backups}"\n'
        f"{func}\n"
        f'install_managed 0644 "{src}" "{dst}"\n'
    )
    assert BASH is not None

    def run() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [BASH, "-c", script], capture_output=True, text=True, timeout=30, check=True
        )

    # Fresh install: nothing to preserve.
    out = run()
    assert dst.read_text() == "shipped\n"
    assert not backups.exists()
    assert "WARN" not in out.stdout
    # Identical file: still nothing to preserve.
    run()
    assert not backups.exists()
    # A local edit is saved before it is replaced.
    dst.write_text("locally edited\n")
    out = run()
    assert dst.read_text() == "shipped\n"
    saved = list(backups.iterdir())
    assert len(saved) == 1
    assert saved[0].read_text() == "locally edited\n"
    assert "previous copy saved" in out.stdout
    assert oct(backups.stat().st_mode & 0o777) == "0o700"


def _load_metrics() -> ModuleType:
    path = ROOT / "deploy" / "monitoring" / "relay-health-metrics.py"
    spec = importlib.util.spec_from_file_location("relay_health_metrics", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_metrics_temp_file_is_not_collectable_and_is_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_metrics()
    seen: list[str] = []
    real = module.tempfile.NamedTemporaryFile

    def spy(*args: object, **kwargs: object) -> object:
        seen.append(str(kwargs.get("suffix")))
        return real(*args, **kwargs)

    monkeypatch.setattr(module.tempfile, "NamedTemporaryFile", spy)
    monkeypatch.setattr(module, "service_active", lambda _name: 1.0)

    def refuse(_url: str) -> tuple[int, object, bytes]:
        raise OSError("offline")

    monkeypatch.setattr(module, "request", refuse)
    out = tmp_path / "relay.prom"
    anchor = tmp_path / "anchor.json"
    monkeypatch.setenv("RELAY_MONITOR_DOMAIN", "relay.example.org")
    monkeypatch.setenv("RELAY_MONITOR_TEXTFILE", str(out))
    monkeypatch.setenv("RELAY_MONITOR_AUDIT_ANCHOR", str(anchor))
    assert module.main() == 0
    assert seen == [".tmp"], "the temp file must not end in .prom (node_exporter globs *.prom)"
    assert [p.name for p in tmp_path.iterdir() if p.suffix == ".prom"] == ["relay.prom"]
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".tmp"], "temp file removed"
    assert os.stat(out).st_mode & 0o777 == 0o644


def _run_probe(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mcp_code: int
) -> str:
    monkeypatch.setattr(module, "service_active", lambda _name: 1.0)

    def fake(url: str) -> tuple[int, object, bytes]:
        if url.endswith("/mcp"):
            return mcp_code, {}, b""
        raise OSError("offline")

    monkeypatch.setattr(module, "request", fake)
    out = tmp_path / "relay.prom"
    monkeypatch.setenv("RELAY_MONITOR_DOMAIN", "relay.example.org")
    monkeypatch.setenv("RELAY_MONITOR_TEXTFILE", str(out))
    monkeypatch.setenv("RELAY_MONITOR_AUDIT_ANCHOR", str(tmp_path / "anchor.json"))
    assert module.main() == 0
    return out.read_text(encoding="utf-8")


@pytest.mark.parametrize(("code", "rejected"), [(401, 1), (403, 1), (200, 0), (500, 0)])
def test_mcp_probe_counts_the_edge_gate_403_as_a_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int, rejected: int
) -> None:
    """A14-D15: the host probes itself, so the CIDR gate answers 403 instead of the app's 401."""
    text = _run_probe(_load_metrics(), tmp_path, monkeypatch, code)
    assert f"relay_mcp_unauthenticated_rejected {float(rejected)}" in text
    assert f"relay_mcp_probe_http_status {float(code)}" in text


@pytest.mark.parametrize(("minor", "accepted"), [("3.12", True), ("3.15", False)])
def test_installer_profile_preflight_precedes_mutations(
    tmp_path: Path, minor: str, accepted: bool
) -> None:
    text = (ROOT / "deploy/install.sh").read_text()
    start = text.index("INSTALL_PYTHON=python3")
    end = text.index('log "Ensuring service account', start)
    fixture_bin = tmp_path / "bin"
    fixture_bin.mkdir()
    interpreter = fixture_bin / "python3"
    interpreter.write_text(f"#!/bin/sh\nprintf '%s\n' '{minor}'\n")
    interpreter.chmod(0o755)
    script = (
        'die() { echo "$*" >&2; exit 1; }; '
        f'PREFIX="{tmp_path / "target"}"; SRC_DIR="{ROOT}";\n' + text[start:end]
    )
    result = subprocess.run(
        ["bash", "-eu", "-c", script],
        env={**os.environ, "PATH": str(fixture_bin) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert (result.returncode == 0) == accepted
    assert not (tmp_path / "target").exists()
    if not accepted:
        assert "no qualified dependency lock" in result.stderr


@pytest.mark.parametrize("dropped", [True, False])
def test_existing_interpreter_probe_requires_service_account(tmp_path: Path, dropped: bool) -> None:
    text = (ROOT / "deploy/install.sh").read_text()
    start = text.index("INSTALL_PYTHON=python3")
    end = text.index('log "Ensuring service account', start)
    target = tmp_path / "target"
    interpreter = target / "venv/bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text('#!/bin/sh\n[ "$PROBE_DROPPED" = yes ] || exit 92\nprintf "3.12\\n"\n')
    interpreter.chmod(0o755)
    fixture_bin = tmp_path / "bin"
    fixture_bin.mkdir()
    sudo = fixture_bin / "sudo"
    sudo.write_text(
        '#!/bin/sh\n[ "$1" = -u ] && [ "$2" = relay-shell ] || exit 91\n'
        + ("export PROBE_DROPPED=yes\n" if dropped else "")
        + 'shift 2\nexec "$@"\n'
    )
    sudo.chmod(0o755)
    result = subprocess.run(
        [
            "bash",
            "-eu",
            "-c",
            "die() { exit 1; }; " + f'PREFIX="{target}"; SRC_DIR="{ROOT}";\n' + text[start:end],
        ],
        env={
            **os.environ,
            "PATH": str(fixture_bin) + os.pathsep + os.environ["PATH"],
            "PROBE_DROPPED": "no",
        },
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert (result.returncode == 0) == dropped
