"""A14-D6: install-edge.sh validates every value before it reaches the Caddyfile."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "install-edge.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is required")

GOOD = {
    "RELAY_SHELL_EDGE_DOMAIN": "relay.example.org",
    "RELAY_SHELL_EDGE_ACME_EMAIL": "ops@example.org",
}


def run(**overrides: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent"}
    env.update(GOOD)
    env.update(overrides)
    env["RELAY_SHELL_EDGE_VALIDATE_ONLY"] = "1"
    assert BASH is not None
    return subprocess.run(
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30, check=False
    )


def test_defaults_and_ordinary_values_pass_without_root() -> None:
    proc = run()
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "Edge values are valid" in proc.stdout
    proc = run(
        RELAY_SHELL_EDGE_CLIENT_CIDRS="10.0.0.0/8 192.168.1.5 2001:db8::/32 ::1",
        RELAY_SHELL_EDGE_UPSTREAM="[::1]:8080",
        RELAY_SHELL_EDGE_ACME_CA="https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("RELAY_SHELL_EDGE_DOMAIN", "rel}ay.example.org"),
        ("RELAY_SHELL_EDGE_DOMAIN", "relay.example.org }\nrespond"),
        ("RELAY_SHELL_EDGE_DOMAIN", "localhost"),
        ("RELAY_SHELL_EDGE_DOMAIN", "relay example.org"),
        ("RELAY_SHELL_EDGE_DOMAIN", "-relay.example.org"),
        ("RELAY_SHELL_EDGE_ACME_EMAIL", "ops@example.org }"),
        ("RELAY_SHELL_EDGE_ACME_EMAIL", "not-an-email"),
        ("RELAY_SHELL_EDGE_ACME_CA", "http://acme.example.org/directory"),
        ("RELAY_SHELL_EDGE_ACME_CA", "https://acme.example.org/dir ectory"),
        ("RELAY_SHELL_EDGE_ACME_CA", 'https://acme.example.org/"x'),
        ("RELAY_SHELL_EDGE_UPSTREAM", "127.0.0.1"),
        ("RELAY_SHELL_EDGE_UPSTREAM", "127.0.0.1:99999"),
        ("RELAY_SHELL_EDGE_UPSTREAM", "127.0.0.1:0"),
        ("RELAY_SHELL_EDGE_UPSTREAM", "127.0.0.1:8080 evil:1"),
        ("RELAY_SHELL_EDGE_CLIENT_CIDRS", "10.0.0.0/8 } respond"),
        ("RELAY_SHELL_EDGE_CLIENT_CIDRS", "10.0.0.0/33"),
        ("RELAY_SHELL_EDGE_CLIENT_CIDRS", "300.1.1.1"),
        ("RELAY_SHELL_EDGE_CLIENT_CIDRS", "2001:db8::/129"),
        ("RELAY_SHELL_EDGE_CLIENT_CIDRS", "not-a-network"),
        ("RELAY_SHELL_EDGE_CLIENT_CIDRS", "10.0.0.0/8\x01"),
    ],
)
def test_malformed_values_are_refused(var: str, value: str) -> None:
    proc = run(**{var: value})
    assert proc.returncode != 0
    assert var in proc.stderr


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
def test_open_cidr_is_accepted_but_warned_about(cidr: str) -> None:
    proc = run(RELAY_SHELL_EDGE_CLIENT_CIDRS=f"10.0.0.0/8 {cidr}")
    assert proc.returncode == 0
    assert "allows every address" in proc.stderr


def test_the_script_still_requires_root_after_validation() -> None:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent", **GOOD}
    assert BASH is not None
    proc = subprocess.run(
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30, check=False
    )
    if os.geteuid() != 0:
        assert proc.returncode != 0
        assert "must run as root" in proc.stderr
