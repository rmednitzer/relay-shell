"""Tests for `relay_shell.verifier` and the `--verify-deploy` CLI flag.

The verifier compares each shipped `deploy/<template>` against the file the
installer is expected to have laid down on the host. Tests build a fake
"install root" under `tmp_path` and exercise each status (OK, DRIFT, MISSING,
ABSENT_TEMPLATE).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from relay_shell.verifier import (
    DEFAULT_PAIRS,
    Status,
    resolve_templates_dir,
    verify_deploy,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / "deploy"
MANAGED_MARKER = "# relay-shell:install-edge:managed"


def _lay_down(install_prefix: Path, install_path: str, content: str) -> Path:
    """Mirror an absolute install path under `install_prefix` and write content."""
    target = install_prefix / install_path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


def _copy_template_into_prefix(install_prefix: Path, name: str) -> Path:
    """Copy a real template into the fake install root, mimicking install.sh."""
    pair = next(p for p in DEFAULT_PAIRS if p.name == name)
    content = (TEMPLATES_DIR / pair.template_rel).read_text()
    # Caddyfile gets the marker prepended by install-edge.sh
    if pair.leader:
        content = pair.leader + "\n" + content
    return _lay_down(install_prefix, pair.install_path, content)


def test_resolve_templates_dir_finds_source_tree() -> None:
    # In an editable install / source checkout, the verifier must locate the
    # deploy/ directory by walking up from the package file.
    path = resolve_templates_dir()
    assert path.is_dir()
    assert (path / "Caddyfile").is_file()
    assert (path / "systemd" / "relay-shell.service").is_file()


def test_verify_deploy_all_ok(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    for pair in DEFAULT_PAIRS:
        _copy_template_into_prefix(prefix, pair.name)
    report = verify_deploy(templates_dir=TEMPLATES_DIR, install_prefix=prefix)
    assert report.ok, [f for f in report.findings if f.status is not Status.OK]
    assert all(f.status is Status.OK for f in report.findings)
    assert len(report.findings) == len(DEFAULT_PAIRS)


def test_verify_deploy_missing(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    # Lay down everything except the logrotate config.
    for pair in DEFAULT_PAIRS:
        if pair.name == "logrotate":
            continue
        _copy_template_into_prefix(prefix, pair.name)
    report = verify_deploy(templates_dir=TEMPLATES_DIR, install_prefix=prefix)
    assert not report.ok
    missing = report.by_status(Status.MISSING)
    assert len(missing) == 1
    assert missing[0].name == "logrotate"
    assert "does not exist" in missing[0].detail


def test_verify_deploy_drift(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    for pair in DEFAULT_PAIRS:
        _copy_template_into_prefix(prefix, pair.name)
    # Tamper with the systemd unit.
    target = prefix / "etc/systemd/system/relay-shell.service"
    target.write_text(target.read_text() + "\n# manually edited on host\n")
    report = verify_deploy(templates_dir=TEMPLATES_DIR, install_prefix=prefix)
    assert not report.ok
    drift = report.by_status(Status.DRIFT)
    assert len(drift) == 1
    assert drift[0].name == "systemd-unit"


def test_verify_deploy_caddyfile_marker_stripped(tmp_path: Path) -> None:
    # install-edge.sh prepends a marker line to /etc/caddy/Caddyfile; the
    # verifier must strip exactly that and still report OK.
    prefix = tmp_path / "root"
    template = (TEMPLATES_DIR / "Caddyfile").read_text()
    _lay_down(prefix, "/etc/caddy/Caddyfile", MANAGED_MARKER + "\n" + template)
    # Lay the others down too so we get a clean report otherwise.
    for pair in DEFAULT_PAIRS:
        if pair.name != "caddyfile":
            _copy_template_into_prefix(prefix, pair.name)
    report = verify_deploy(templates_dir=TEMPLATES_DIR, install_prefix=prefix)
    caddy = next(f for f in report.findings if f.name == "caddyfile")
    assert caddy.status is Status.OK


def test_verify_deploy_caddyfile_drift_under_marker(tmp_path: Path) -> None:
    # A drift inside the body (after the marker) still surfaces.
    prefix = tmp_path / "root"
    tampered = MANAGED_MARKER + "\n" + (TEMPLATES_DIR / "Caddyfile").read_text() + "\nextra\n"
    _lay_down(prefix, "/etc/caddy/Caddyfile", tampered)
    for pair in DEFAULT_PAIRS:
        if pair.name != "caddyfile":
            _copy_template_into_prefix(prefix, pair.name)
    report = verify_deploy(templates_dir=TEMPLATES_DIR, install_prefix=prefix)
    caddy = next(f for f in report.findings if f.name == "caddyfile")
    assert caddy.status is Status.DRIFT


def test_verify_deploy_absent_template_when_dir_missing(tmp_path: Path) -> None:
    # Point at a directory that contains no templates.
    empty = tmp_path / "no-templates"
    empty.mkdir()
    report = verify_deploy(templates_dir=empty, install_prefix=tmp_path)
    assert not report.ok
    assert all(f.status is Status.ABSENT_TEMPLATE for f in report.findings)


# --- CLI subprocess tests (close the integration loop) -----------------------


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "relay_shell", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_verify_deploy_ok_exits_zero(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    for pair in DEFAULT_PAIRS:
        _copy_template_into_prefix(prefix, pair.name)
    proc = _run_cli(
        "--verify-deploy",
        "--templates-dir",
        str(TEMPLATES_DIR),
        "--install-prefix",
        str(prefix),
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
    assert "verify-deploy OK" in proc.stderr


def test_cli_verify_deploy_drift_exits_two(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    for pair in DEFAULT_PAIRS:
        _copy_template_into_prefix(prefix, pair.name)
    target = prefix / "etc/logrotate.d/relay-shell"
    target.write_text("# tampered\n")
    proc = _run_cli(
        "--verify-deploy",
        "--templates-dir",
        str(TEMPLATES_DIR),
        "--install-prefix",
        str(prefix),
    )
    assert proc.returncode == 2
    assert "DRIFT" in proc.stdout
    assert "verify-deploy FAILED" in proc.stderr


def test_cli_verify_deploy_json(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    for pair in DEFAULT_PAIRS:
        _copy_template_into_prefix(prefix, pair.name)
    # Remove one to force a non-OK result.
    (prefix / "etc/systemd/system/relay-shell.service").unlink()
    proc = _run_cli(
        "--verify-deploy",
        "--json",
        "--templates-dir",
        str(TEMPLATES_DIR),
        "--install-prefix",
        str(prefix),
    )
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    names = {f["name"]: f["status"] for f in payload["findings"]}
    assert names["systemd-unit"] == "MISSING"
    assert names["logrotate"] == "OK"
