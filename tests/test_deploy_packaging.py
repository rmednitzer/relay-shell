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
