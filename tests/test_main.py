"""End-to-end tests for the ``python -m relay_shell`` entrypoint.

These exercise the process-level surface (`__main__.main`):

* ``--check-config`` (B-013) - validate config + build server, no transport.
* The pre-existing print-and-return-2 path for invalid configuration
  (T-001 from `docs/runbook.md` section 5.3).

We use real subprocess invocations rather than calling ``main()`` in
the test process: argparse + ``get_settings`` + ``build_server`` together
touch process-global state that's awkward to roll back.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _run_main(
    args: list[str],
    *,
    env_extra: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # Strip any inherited RELAY_SHELL_* so the test controls the surface.
    for key in list(env):
        if key.startswith("RELAY_SHELL_"):
            del env[key]
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "relay_shell", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None,
        timeout=30,
    )


def test_check_config_succeeds_on_valid_env(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    proc = _run_main(
        ["--check-config"],
        env_extra={
            "RELAY_SHELL_AUDIT_PATH": str(audit),
            "RELAY_SHELL_SSH_CONFIG": str(tmp_path / "no_cfg"),
            "RELAY_SHELL_POLICY_MODE": "open",
        },
    )
    assert proc.returncode == 0, proc.stderr
    # All output is on stderr (stdio transport contract).
    assert "config OK" in proc.stderr
    assert "transport=stdio" in proc.stderr
    assert "policy=open" in proc.stderr
    # The audit file was opened (--check-config is intended to *prove* this).
    assert audit.exists()


def test_check_config_rejects_invalid_transport(tmp_path: Path) -> None:
    proc = _run_main(
        ["--check-config"],
        env_extra={
            "RELAY_SHELL_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
            "RELAY_SHELL_SSH_CONFIG": str(tmp_path / "no_cfg"),
            "RELAY_SHELL_TRANSPORT": "bogus",
        },
    )
    assert proc.returncode == 2
    assert "invalid configuration" in proc.stderr
    assert "transport" in proc.stderr


def test_check_config_help_lists_the_flag() -> None:
    proc = _run_main(["--help"])
    assert proc.returncode == 0
    # argparse writes --help output to stdout.
    assert "--check-config" in proc.stdout
    assert "CI pipelines" in proc.stdout


def test_main_returns_two_on_invalid_config_without_check_flag(tmp_path: Path) -> None:
    """T-001 from runbook section 5.3: main() exits 2 on invalid config.

    Without --check-config the entrypoint would normally try to start
    the transport. We pass an invalid RELAY_SHELL_TRANSPORT so it bails
    at get_settings() and never reaches build_server, exercising the
    print-and-return-2 path that previously had no test.
    """
    proc = _run_main(
        [],
        env_extra={
            "RELAY_SHELL_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
            "RELAY_SHELL_SSH_CONFIG": str(tmp_path / "no_cfg"),
            "RELAY_SHELL_TRANSPORT": "definitely-not-a-transport",
        },
    )
    assert proc.returncode == 2
    assert "invalid configuration" in proc.stderr
