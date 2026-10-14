"""A14-C3b: a redacted value must not swallow the shell command glued to it.

Pre-fix, ``token=a;rm -rf /srv`` was audited as ``token=[REDACTED] -rf /srv`` (the value
ran on past the ``;``), so the destructive command's name vanished from the record.
Synthetic secrets only.
"""

from __future__ import annotations

import time

import pytest

from relay_shell import patterns
from relay_shell.redaction import _scrub_str, redact

SECRET = "S3cr3tVALUE"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (f"x=1 token={SECRET};rm -rf /srv", "x=1 token=[REDACTED];rm -rf /srv"),
        (f"password={SECRET}&&rm x", "password=[REDACTED]&&rm x"),
        (f"API_KEY={SECRET}||rm x", "API_KEY=[REDACTED]||rm x"),
        (f"token={SECRET}|cat /etc/passwd", "token=[REDACTED]|cat /etc/passwd"),
        (f"secret={SECRET}&rm x", "secret=[REDACTED]&rm x"),
        (f"AWS_SECRET_ACCESS_KEY={SECRET};rm x", "AWS_SECRET_ACCESS_KEY=[REDACTED];rm x"),
        (f"cmd --password {SECRET};rm -rf /srv", "cmd --password [REDACTED];rm -rf /srv"),
        (f"cmd --token={SECRET}&&rm x", "cmd --token=[REDACTED]&&rm x"),
        (f"cmd -token {SECRET}|tee x", "cmd -token [REDACTED]|tee x"),
        (f"mysql -p{SECRET};rm x", "mysql -p[REDACTED];rm x"),
        (f"curl -u user:{SECRET};rm x", "curl -u user:[REDACTED];rm x"),
        (f"sshpass -p {SECRET};rm x", "sshpass -p [REDACTED];rm x"),
        (f"docker login -p {SECRET}&&rm x", "docker login -p [REDACTED]&&rm x"),
        (f"openssl x -pass pass:{SECRET};rm y", "openssl x -pass pass:[REDACTED];rm y"),
        (f"ConvertTo-SecureString {SECRET};rm x", "ConvertTo-SecureString [REDACTED];rm x"),
        (f"GET /?token={SECRET}&user=bob HTTP", "GET /?token=[REDACTED]&user=bob HTTP"),
    ],
)
def test_value_stops_at_a_shell_control_operator(command: str, expected: str) -> None:
    out = redact(command)
    assert out == expected
    assert SECRET not in out


@pytest.mark.parametrize(
    "command",
    [
        f"echo 'DB_PASSWORD={SECRET};tail' > .env",
        f'echo "token={SECRET}|tail"',
        f"printf 'api_key={SECRET}&&tail\\n'",
    ],
)
def test_value_inside_a_quoted_string_is_consumed_whole(command: str) -> None:
    """The operator is data inside quotes: the whole secret, tail included, must go."""
    out = redact(command)
    assert SECRET not in out
    assert "tail" not in out


@pytest.mark.parametrize(
    "command",
    [
        "token=Sec\\;ret next",
        "cmd --password Sec\\;ret next",
    ],
)
def test_escaped_operator_stays_part_of_the_secret(command: str) -> None:
    out = redact(command)
    assert "Sec" not in out
    assert "ret" not in out.replace("[REDACTED]", "")
    assert out.endswith(" next")


@pytest.mark.parametrize(
    "command",
    [
        f"token={SECRET}",
        f"password: {SECRET} and more",
        f'--password "{SECRET} with spaces"',
        f"PASSWORD='{SECRET} two'",
        f"cmd --api-key={SECRET}",
    ],
)
def test_values_without_operators_are_redacted_as_before(command: str) -> None:
    out = redact(command)
    assert SECRET not in out
    assert "[REDACTED]" in out


def test_accepted_limit_unquoted_secret_with_operator_is_cut_at_it() -> None:
    """Documented trade-off (PATTERNS_VERSION 15): the part before the operator is
    redacted; an unquoted ``;`` ends a shell word, so the rest is a separate word."""
    assert redact("token=ab;cd") == "token=[REDACTED];cd"


def test_patterns_version_bumped() -> None:
    assert int(patterns.PATTERNS_VERSION) >= 15


@pytest.mark.parametrize(
    "payload",
    [
        "token=a;" * 5000,
        "token=" + "a;" * 8000,
        "password=" + "&|" * 8000,
        ("password=" + "x" * 300 + ";") * 100,
        "token=" + "a" * 200_000,
    ],
)
def test_operator_aware_values_stay_linear(payload: str) -> None:
    started = time.perf_counter()
    _scrub_str(payload, 500)
    assert time.perf_counter() - started < 1.0
