from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "healthcheck.sh"


@pytest.mark.parametrize(
    ("status", "exit_code", "healthy"),
    [
        ("200", 0, True),
        ("401", 0, True),
        ("403", 0, True),
        ("404", 0, True),
        ("503", 0, True),  # This is liveness, not application readiness.
        ("000", 7, False),  # Connection refused: curl itself emits 000.
        ("000", 28, False),  # Timeout.
        ("200", 28, False),  # Headers arrived, but the request failed later.
        ("", 7, False),
        ("000", 0, False),
        ("000000", 0, False),
        ("garbage", 0, False),
    ],
)
def test_healthcheck_transport_status(
    tmp_path: Path, status: str, exit_code: int, healthy: bool
) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("healthcheck requires bash")
    curl = tmp_path / "curl"
    curl.write_text(
        '#!/bin/sh\nprintf "%s" "$FAKE_CURL_STATUS"\nexit "$FAKE_CURL_EXIT"\n',
        encoding="utf-8",
    )
    curl.chmod(0o755)
    result = subprocess.run(
        [bash, str(SCRIPT)],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.defpath,
            "FAKE_CURL_STATUS": status,
            "FAKE_CURL_EXIT": str(exit_code),
            "RELAY_SHELL_HTTP_HOST": "127.0.0.1",
            "RELAY_SHELL_HTTP_PORT": "18080",
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == (0 if healthy else 1), result.stderr
    assert ("relay-shell: ok" in result.stdout) is healthy
    assert ("UNHEALTHY" in result.stdout) is not healthy
