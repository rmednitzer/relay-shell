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


def test_redact_cli_flag_single_dash_long_name() -> None:
    # Go-flavored tools (and a few legacy CLIs) use a single dash for long-name
    # flags: ``-token=foo``, ``-password value``. The redactor catches these to
    # avoid leaking secrets just because the tool dropped a dash.
    assert "go-secret" not in redact("mytool -token=go-secret -verbose")
    assert "another-secret" not in redact("mytool -password another-secret --quiet")


def test_redact_cli_flag_does_not_eat_next_flag() -> None:
    # ``--password`` with no value (interactive prompt) followed by another
    # flag must not cause ``--host`` to be redacted as if it were the secret.
    out = redact("mysql --password --host db.example -u root")
    assert "--host" in out
    assert "db.example" in out
    # ``--token`` followed by ``--quiet`` likewise leaves ``--quiet`` intact.
    out2 = redact("client --token --quiet")
    assert "--quiet" in out2


def test_redact_cli_flag_handles_quoted_value() -> None:
    # Quoted passphrase-style secrets must be scrubbed as a unit, not just
    # up to the first whitespace.
    out = redact('--password "top secret pass" --host db')
    assert "top secret" not in out
    assert "secret" not in out
    assert "--host" in out and "db" in out
    # Single quotes too.
    out2 = redact("--token 'super secret value'")
    assert "super secret" not in out2
    # Escape-aware: inner ``\"`` does not end the quoted region.
    out3 = redact(r'--password "esc\"aped value" --next')
    assert "aped value" not in out3
    assert "--next" in out3


def test_redact_cli_flag_handles_backslash_escaped_space() -> None:
    # Shell-style ``--password top\ secret`` must scrub the whole value, not
    # just up to the unescaped space. Common when avoiding quotes.
    out = redact(r"--password top\ secret --host db")
    assert "secret" not in out
    assert "--host" in out and "db" in out


def test_cli_flag_separator_does_not_cross_newline() -> None:
    # ``--password`` with no value (interactive prompt) followed by a newline
    # and a separate command must not redact the next line's first token.
    script = "mysql --password\necho hello-world\n"
    out = redact(script)
    assert "echo hello-world" in out
    # Same for ``--token`` at end of line.
    out2 = redact("client --token\nls -la\n")
    assert "ls -la" in out2


def test_short_dash_p_is_intentionally_not_redacted() -> None:
    # ``-p`` is overloaded across tools (mysql password, ssh/nmap port,
    # ``-proxy``, ...) and we deliberately do not try to scrub the short
    # form. Operators must use the long form (``--password=...``) or
    # interactive ``-p`` / ``~/.my.cnf`` instead. Audit fidelity for
    # unrelated ``-p`` flags wins over a brittle MySQL heuristic.
    assert "leaked-pw" in redact("mysql -uroot -pleaked-pw -h db")
    # And the negatives (overloaded ``-p`` uses) keep their audit text.
    assert "-p22" in redact("ssh -p22 user@host")
    assert "-p1-1000" in redact("nmap -p1-1000 host.example")
    assert "-proxy" in redact("java -proxy host:8080 -jar app.jar")
    # ``--protocol`` (long option starting with ``--p...``) is untouched.
    assert "--protocol=tcp" in redact("mysql --protocol=tcp -uroot mydb")


def test_redact_args_preserves_non_strings() -> None:
    out = redact_args({"n": 5, "b": True, "x": None, "lst": [1, 2]})
    assert out["n"] == 5
    assert out["b"] is True
    assert out["x"] is None
    assert out["lst"] == [1, 2]
