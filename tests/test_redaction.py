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


def test_dash_p_does_not_match_long_option_value() -> None:
    # ``--protocol`` starts with two dashes; the ``-p`` regex must not start
    # at the second dash and rewrite the option name.
    out = redact("mysql --protocol=tcp -uroot mydb")
    assert "--protocol=tcp" in out


def test_dash_p_scoping_is_per_line() -> None:
    # In a multi-line script, a ``mysql`` line must not enable ``-p`` scrub
    # on unrelated lines (e.g. an ``ssh -p22 host`` later in the script).
    script = "mysql -puploaded-secret -h db\nssh -p22 user@host\n"
    out = redact(script)
    assert "uploaded-secret" not in out
    assert "-p22" in out
    assert "user@host" in out


def test_redact_mysql_dash_p_only_in_db_context() -> None:
    # In MySQL-family context, ``-p<secret>`` is scrubbed in place.
    assert "leaked" not in redact("mysql -uroot -pleaked-pw -h db")
    assert "leaked" not in redact("mysqldump -pleaked-pw mydb > dump.sql")
    assert "leaked" not in redact("mariadb -pleaked-pw -e 'show databases'")
    # Outside that context, ``-p`` is overloaded and must be left intact:
    # SSH port, nmap port range, and generic flags like ``-proxy``.
    safe = redact("ssh -p 22 user@host")
    assert "22" in safe and "user" in safe
    compact = redact("ssh -p22 user@host")
    assert "-p22" in compact and "user@host" in compact
    nmap = redact("nmap -p1-1000 host.example")
    assert "-p1-1000" in nmap
    proxy = redact("java -proxy host:8080 -jar app.jar")
    assert "-proxy" in proxy


def test_redact_args_preserves_non_strings() -> None:
    out = redact_args({"n": 5, "b": True, "x": None, "lst": [1, 2]})
    assert out["n"] == 5
    assert out["b"] is True
    assert out["x"] is None
    assert out["lst"] == [1, 2]
