from __future__ import annotations

from relay_shell.redaction import redact, redact_args


def test_redact_bearer_and_kv() -> None:
    assert "REDACTED" in redact("Authorization: Bearer abcdef123456")
    assert "REDACTED" in redact("api_key=supersecretvalue")
    assert "REDACTED" in redact("password: hunter2")


def test_redact_token_shapes() -> None:
    assert "REDACTED" in redact("github_pat_11ABCDEF_xxxxxxxxxxxxxxxxxxxx")
    assert "REDACTED" in redact("ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert "REDACTED" in redact("sk-abcdefghijklmnopqrstuv")


def test_redact_private_key_block() -> None:
    blob = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
    assert "AAAA" not in redact(blob)


def test_redact_url_credentials() -> None:
    assert "://[REDACTED]@" in redact("https://user:pass@host/repo.git")


def test_redact_args_truncates_and_scrubs() -> None:
    args = {"command": "echo " + "x" * 2000, "token": "Bearer zzzzzzzzzzzz"}
    out = redact_args(args, max_len=100)
    assert len(out["command"]) <= 120
    assert "REDACTED" in out["token"]


def test_redact_args_nested() -> None:
    out = redact_args({"a": {"b": ["password=topsecret"]}})
    assert "REDACTED" in out["a"]["b"][0]


def test_redact_cli_flag_forms() -> None:
    assert "topsecret" not in redact("--password topsecret extra-arg")
    assert "topsecret" not in redact("--password=topsecret")
    assert "MY-TOKEN" not in redact("--token MY-TOKEN")
    assert "abcd1234" not in redact("--api-key abcd1234 --quiet")


def test_redact_mysql_dash_p() -> None:
    assert "leaked" not in redact("mysql -uroot -pleaked-pw -h db")
    # Negative: -p as flag with no value (e.g. ``ssh -p 22``) must not bleed.
    safe = redact("ssh -p 22 user@host")
    assert "22" in safe and "user" in safe


def test_redact_args_preserves_non_strings() -> None:
    out = redact_args({"n": 5, "b": True, "x": None, "lst": [1, 2]})
    assert out["n"] == 5
    assert out["b"] is True
    assert out["x"] is None
    assert out["lst"] == [1, 2]
