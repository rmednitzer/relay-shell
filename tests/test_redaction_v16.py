"""A14-C8b: remaining redaction gaps (PATTERNS_VERSION 16). Synthetic secrets only."""

from __future__ import annotations

import time

import pytest

from relay_shell.redaction import _scrub_str, redact

SECRET = "Hunt3r2Secret"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"password := {SECRET} next", "password := [REDACTED] next"),
        (f"password => {SECRET} next", "password => [REDACTED] next"),
        (f"$c = @{{ password => '{SECRET}' }}", "$c = @{ password => '[REDACTED]' }"),
        (f"api_key:={SECRET};ls", "api_key:=[REDACTED];ls"),
        (f"curl https://{SECRET}tokenvalue@host/x", "curl https://[REDACTED]@host/x"),
        (
            f"aws configure set aws_secret_access_key {SECRET}/xyz next",
            "aws configure set aws_secret_access_key [REDACTED] next",
        ),
        (
            f"aws configure set --profile p aws_session_token '{SECRET} q' x",
            "aws configure set --profile p aws_session_token [REDACTED] x",
        ),
        (f"redis-cli -a {SECRET} ping", "redis-cli -a [REDACTED] ping"),
        (f"redis-cli -h h -a '{SECRET} q' ping", "redis-cli -h h -a [REDACTED] ping"),
        (f"redis-cli --pass {SECRET} get x", "redis-cli --pass [REDACTED] get x"),
        (f"unzip -P {SECRET} a.zip", "unzip -P [REDACTED] a.zip"),
        (f"zip -P{SECRET} out.zip f", "zip -P[REDACTED] out.zip f"),
        (f"ldapsearch -x -w {SECRET} -b dc=x", "ldapsearch -x -w [REDACTED] -b dc=x"),
        (f"ldapmodify -w '{SECRET}' -f x.ldif", "ldapmodify -w [REDACTED] -f x.ldif"),
    ],
)
def test_remaining_gaps_are_redacted(text: str, expected: str) -> None:
    out = redact(text)
    assert out == expected
    assert SECRET not in out


@pytest.mark.parametrize(
    "text",
    [
        "aws configure set region eu-west-1",
        "aws s3 ls -a",
        "redis-cli -h cache ping",
        "ls -a docs",
        "unzip -p a.zip file | head",
        "unzip -o a.zip",
        "ldapsearch -x -W -b dc=x",
        "ldapsearch -x -b dc=x -D cn=admin",
        "git clone ssh://git@github.com/x/y",
        "curl https://user@example.org/x",
        "curl https://shortname@host/",
        "ssh user@host",
        "password and more words",
        "password: ",
    ],
)
def test_near_misses_are_left_alone(text: str) -> None:
    assert "[REDACTED]" not in redact(text)


def test_unterminated_pem_block_is_collapsed() -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 30
    for text in (
        f"-----BEGIN PRIVATE KEY-----\n{body}",
        f"-----BEGIN RSA PRIVATE KEY----- {body} and more",
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n",
    ):
        out = redact(text)
        assert body[:40] not in out
        assert "[REDACTED]" in out


def test_terminated_pem_block_keeps_its_tail() -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 4
    out = redact(f"cmd <<EOF\n-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\nEOF")
    assert body not in out
    assert out.endswith("\nEOF")


def test_unterminated_pem_survives_truncation_of_the_audit_record() -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 40
    record = _scrub_str(f"-----BEGIN PRIVATE KEY-----\n{body}", 500)
    assert body[:40] not in record


@pytest.mark.parametrize(
    "payload",
    [
        "-----BEGIN PRIVATE KEY-----" * 2000,
        "-----BEGIN PRIVATE KEY-----\n" + "A" * 200_000,
        "aws configure set " * 4000,
        "redis-cli -a " * 6000,
        "unzip " * 8000,
        "ldapsearch " * 6000,
        "password := " * 6000,
        "https://" + "a" * 100_000 + "@",
        ("https://" + "a" * 20 + "@") * 3000,
    ],
)
def test_new_rules_are_linear_on_adversarial_input(payload: str) -> None:
    started = time.perf_counter()
    _scrub_str(payload, 500)
    assert time.perf_counter() - started < 2.0
