from __future__ import annotations

from relay_shell.redaction import _scrub_str, redact, redact_args


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


def test_p1_scan_is_bounded_and_lossless() -> None:
    # P1 (2026-07-15 perf pass): _scrub_str scans only max_len + a margin, then
    # truncates to max_len — the dropped tail is never in the record, so bounding
    # the scan cannot leak a secret it would otherwise catch. A ~2 MB argument
    # must scrub in well under the old whole-string cost, a secret inside the
    # kept window is still redacted, and a secret only in the far tail is simply
    # truncated away (absent from the record).
    import time

    head = 'password="EARLYSECRET" ' + "a" * 400
    tail = ' password="TAILSECRET_FARAWAY"'
    payload = head + "b" * (2 * 1024 * 1024) + tail  # ~2 MB, secret at each end
    t0 = time.perf_counter()
    out = redact_args({"env_json": payload})["env_json"]
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, f"redact_args took {elapsed:.2f}s — scan not bounded?"
    assert "EARLYSECRET" not in out  # in-window secret redacted
    assert "TAILSECRET_FARAWAY" not in out  # far-tail secret truncated out
    assert out.endswith(")")  # carries the "...(+N)" truncation marker


def test_p1_preserves_output_for_normal_size_args() -> None:
    # An argument that fits inside the scan window is byte-identical to the
    # pre-P1 output (no behaviour change for realistic inputs).
    args = {"command": "echo " + "x" * 2000, "token": "Bearer zzzzzzzzzzzz"}
    out = redact_args(args, max_len=100)
    assert len(out["command"]) <= 120 and out["command"].startswith("echo ")
    assert "REDACTED" in out["token"]


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


def test_redact_cli_flag_redacts_single_dash_prefixed_values() -> None:
    # Some CLIs accept dash-prefixed values for required arguments, and those
    # values must still be scrubbed when passed as the next argv token.
    out = redact("client --token -abc123DashSecret --quiet")
    assert "-abc123DashSecret" not in out
    assert "--quiet" in out
    out2 = redact("mysql --password -secret123 --host db")
    assert "-secret123" not in out2
    assert "--host" in out2 and "db" in out2


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


def test_red8_quoted_secret_past_scan_window_does_not_leak_tail() -> None:
    # RED-8: a quoted CLI-flag secret longer than the redaction scan window
    # (`_scrub_str` scans only `max_len + 16 KiB`) loses its closing quote to
    # truncation. Before the unterminated-quote fallback branches, the quoted
    # regex branch could not match the truncated value and the greedy bare
    # fallback stopped at the first internal space, leaking the value's tail
    # into the length-bounded audit record. Full-string redaction always caught
    # it, so this was a P1 scan-window regression, not a pattern gap.
    marker = "LEAKMARKER"
    # ~20 KiB quoted value, internal spaces, closing quote well past the window.
    value = "a " + (("z" * 40 + " " + marker + " ") * 400)
    arg = f'--password="{value}"'
    assert len(arg) > 500 + 16384  # closing quote is outside the scan window

    scrubbed = _scrub_str(arg, 500)
    assert marker not in scrubbed, "quoted secret tail leaked past the scan window"
    assert scrubbed.startswith("--password=[REDACTED]")

    # And full-string redaction (whole value in view) collapses it as before.
    assert marker not in redact(arg)


def test_red8_unterminated_quote_is_redacted_but_wellformed_unchanged() -> None:
    # The unterminated-quote fallback fires only when the terminated branch
    # fails, so well-formed quoted values are byte-identical, and a genuinely
    # unterminated quote is still collapsed (audit-fidelity tradeoff, not a leak).
    # Well-formed: trailing content after the closing quote is preserved.
    assert redact('--password="top secret" --host=h') == "--password=[REDACTED] --host=h"
    # Unterminated single-line quote: the whole visible value collapses.
    out = redact('--token="abc def ghi')  # no closing quote
    assert "abc" not in out and "def" not in out and "ghi" not in out
    assert out.startswith("--token=[REDACTED]")


def test_win1_credential_keyword_redacted() -> None:
    # WIN-1 / ADR 0011 increment C: PowerShell `-Credential`, connection-string
    # `credential=`, and JSON `"credential":` shapes must not reach the audit log.
    assert redact("-Credential MyP@ssw0rd") == "-Credential [REDACTED]"
    assert "secret123" not in redact("--credential=secret123")
    assert "connsecret" not in redact("Server=x;credential=connsecret;Db=y")
    assert "jsonsecret" not in redact('{"credential": "jsonsecret"}')


def test_win1_convertto_securestring_inline_plaintext_redacted() -> None:
    # WIN-1: the canonical pwsh idiom for inlining a secret. The quoted or bare
    # literal operand of ConvertTo-SecureString is collapsed, in the positional,
    # -String, and flags-before-value forms.
    for inp, secret in (
        ("ConvertTo-SecureString 'P@ss123' -AsPlainText -Force", "P@ss123"),
        ('ConvertTo-SecureString -String "Sekret99" -AsPlainText', "Sekret99"),
        ("ConvertTo-SecureString BarePass77 -AsPlainText -Force", "BarePass77"),
        ("ConvertTo-SecureString -AsPlainText -Force PlainX9", "PlainX9"),
    ):
        out = redact(inp)
        assert secret not in out, inp
        assert "[REDACTED]" in out, inp

    # Negatives: an already-encrypted `$var` handle (not plaintext) and the bare
    # switches must never be over-scrubbed.
    out = redact("ConvertTo-SecureString $encrypted -Key $k")
    assert "$encrypted" in out and "$k" in out
    assert "[REDACTED]" not in out


def test_win1_verb_noun_cmdlet_not_overscrubbed() -> None:
    # The `(?<![A-Za-z])` guard keeps the CLI-flag rule from binding the dash of
    # a PowerShell Verb-Noun cmdlet (`Get-Credential`, `Get-Secret`), which
    # contains `-Credential`/`-Secret` but takes no inline secret — so the next
    # token (a message, a name) must survive.
    assert redact("Get-Credential -Message hi") == "Get-Credential -Message hi"
    assert redact("Get-Secret Foo") == "Get-Secret Foo"
    assert redact("Remove-Secret Bar") == "Remove-Secret Bar"
    # But a genuine secret flag (preceded by whitespace / start) still redacts.
    assert redact("cmd -Secret abc123") == "cmd -Secret [REDACTED]"
    assert "hunter2" not in redact("--password hunter2")


def test_win1_convertto_securestring_is_redos_bounded() -> None:
    # The ConvertTo-SecureString rule skips leading switches with a bounded
    # `{0,8}?` gap (RED-7 discipline); a large argument that repeats the cmdlet
    # with only switches (never an operand) must stay linear.
    import time

    payload = "ConvertTo-SecureString -AsPlainText " * 100000  # ~3.6 MB, no operand
    t0 = time.perf_counter()
    redact(payload)
    elapsed = time.perf_counter() - t0
    assert elapsed < 3.0, f"redact() took {elapsed:.1f}s — possible ReDoS regression"


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


def test_short_dash_p_is_redacted_for_mysql_family_only() -> None:
    # Compact ``-p<value>`` is redacted for MySQL-family command names,
    # including related utilities that begin with mysql/mariadb.
    assert "leaked-pw" not in redact("mysql -uroot -pleaked-pw -h db")
    assert "leaked" not in redact("mysqlshow -uroot -pleaked db")
    assert "leaked" not in redact("mysqlcheck -uroot -pleaked db")
    assert "leaked" not in redact("mariadb-dump -uroot -pleaked db")
    # Overloaded non-MySQL ``-p`` forms keep audit fidelity.
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


# Stripe / GitLab token shapes are recognised by GitHub secret-scanning
# push protection, which would block this file from being pushed. Assemble
# the synthetic fixtures from parts so no contiguous token literal appears
# in the source while `redact` still sees the identical value.
_GOOGLE = "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
_STRIPE = "sk_live_" + "0123456789abcdefABCDEFgh"
_GLPAT = "glpat-" + "ABCDEF1234567890abcd"
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"


def test_redact_provider_tokens_arriving_bare_in_args() -> None:
    # The realistic leak path: a secret arrives bare in a tool argument
    # (a JSON request body, a config blob, a flag the CLI-flag list does
    # not name) rather than behind a known `--password`/`Bearer` prefix.
    # The structurally-anchored provider patterns are the safety net.
    body = f'{{"google": "{_GOOGLE}", "stripe": "{_STRIPE}", "id_token": "{_JWT}"}}'
    out = redact(body)
    for leaked in (_GOOGLE, _STRIPE, "eyJzdWIiOiIxMjM0NTY3ODkwIn0"):
        assert leaked not in out, leaked
    # The surrounding JSON keys (non-secret structure) survive so the
    # audit record stays useful.
    assert '"google"' in out and '"stripe"' in out and '"id_token"' in out


def test_redact_args_scrubs_nested_provider_tokens() -> None:
    # End-to-end through redact_args: a token nested in a list inside a
    # dict (the shape audit args take) is still scrubbed.
    out = redact_args({"env": {"keys": [_GLPAT]}})
    assert _GLPAT not in out["env"]["keys"][0]
    assert "[REDACTED]" in out["env"]["keys"][0]


# --- RED-3: additional cloud/provider secret shapes -------------------------

# Assemble synthetic fixtures from parts so no contiguous real-looking secret
# literal appears in source (GitHub push protection is separate from the
# gitleaks allowlist), while `redact` still sees the identical value.
_AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEX" + "AMPLEKEY"
_AZURE_KEY = "Zm9vYmFy" + "YmF6cXV4MTIzNDU2" + "Nzg5MA=="
_AZURE_SIG = "aBcDeFgHiJkLmNoP" + "qRsT%2FuVwXyZ" + "0123456789"
_SLACK_HOOK = (
    "https://hooks.slack.com/services/" + "T00000000/" + "B11111111/" + "abcdefghijkLMNOpqrstuvwx"
)


def test_red3_aws_secret_access_key_assignment() -> None:
    # `secret` sits mid-name in AWS_SECRET_ACCESS_KEY=, which the generic
    # `secret=` rule misses; the phrase-anchored rule catches it.
    for line in (
        f"AWS_SECRET_ACCESS_KEY={_AWS_SECRET}",
        f"export aws_secret_access_key={_AWS_SECRET}",
        f"secret_access_key = {_AWS_SECRET}",
    ):
        out = redact(line)
        assert _AWS_SECRET not in out, line
        assert "[REDACTED]" in out
    # Negative: a *_PATH var (the `_PATH` breaks key[:=] adjacency) survives.
    assert "[REDACTED]" not in redact("SECRET_ACCESS_KEY_PATH=/etc/aws/creds")


def test_red3_azure_connection_string_keys() -> None:
    conn = (
        "DefaultEndpointsProtocol=https;AccountName=acct;"
        f"AccountKey={_AZURE_KEY};EndpointSuffix=core.windows.net"
    )
    out = redact(conn)
    assert _AZURE_KEY not in out
    # Non-secret structure preserved for the audit reader.
    assert "AccountName=acct" in out and "EndpointSuffix=core.windows.net" in out
    # Service Bus / Event Hubs SharedAccessKey.
    sb = f"Endpoint=sb://x;SharedAccessKeyName=root;SharedAccessKey={_AZURE_KEY}"
    assert _AZURE_KEY not in redact(sb)
    # Negative: AccountName is not a secret key.
    assert "[REDACTED]" not in redact("AccountName=mystorageacct")


def test_red3_azure_sas_signature() -> None:
    url = f"https://x.blob.core.windows.net/c/b?sv=2021-08-06&se=2025-01-01&sig={_AZURE_SIG}"
    out = redact(url)
    assert _AZURE_SIG not in out
    assert "sv=2021-08-06" in out and "se=2025-01-01" in out  # non-secret params survive
    # Negatives: `design=`/`sign=` substrings (no ?/& sig= boundary), and a
    # tiny sig= below the length floor, are left for audit fidelity.
    assert "[REDACTED]" not in redact("https://x/?design=modern&page=2")
    assert "[REDACTED]" not in redact("https://x/?sig=short")


def test_red3_slack_webhook_url() -> None:
    out = redact(f"curl -X POST {_SLACK_HOOK} -d @msg.json")
    assert _SLACK_HOOK not in out
    assert "[REDACTED]" in out
    # Negative: a non-webhook hooks.slack.com path is not collapsed.
    assert "[REDACTED]" not in redact("https://hooks.slack.com/help")


# --- RED-4 / RED-5: scrub robustness ----------------------------------------


def test_red4_bytes_args_are_decoded_and_redacted() -> None:
    # A bytes argument used to fall through unredacted; it is now decoded
    # (lossy) and scrubbed like a str.
    out = redact_args({"payload": b"api_key=supersecretvalue123"})
    assert "supersecretvalue123" not in out["payload"]
    assert "[REDACTED]" in out["payload"]
    # Invalid UTF-8 does not raise (errors="replace").
    out2 = redact_args({"raw": b"\xff\xfetoken=leakme1234567890"})
    assert "leakme1234567890" not in out2["raw"]


def test_red5_dict_keys_are_scrubbed() -> None:
    # A secret carried in a (nested) dict *key*, not just a value, is scrubbed.
    out = redact_args({"body": {"token=abc123def456ghi": "x", "host": "ok"}})
    keys = set(out["body"].keys())
    assert "token=[REDACTED]" in keys
    assert "host" in keys  # ordinary keys untouched
    assert "abc123def456ghi" not in " ".join(keys)
