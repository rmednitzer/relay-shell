from __future__ import annotations

from mcpx.redaction import redact, redact_args


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
