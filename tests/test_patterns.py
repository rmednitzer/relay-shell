"""Anchor tests for the compiled regex tables.

These exist alongside ``tests/test_redaction.py`` and ``tests/test_policy.py``
to make pattern changes auditable as a one-file diff:

* the tables compile and re-export under the expected names,
* the redactor and the classifier consume the same compiled objects
  (no silent shadowing or accidental re-compilation in the executor), and
* every pattern has at least one positive case and one near-miss
  negative case (over-scrub / under-scrub for redaction, classify /
  near-miss for policy heuristics).

If you add a pattern in ``patterns.py``, also add a pair here.
"""

from __future__ import annotations

import re

from relay_shell import patterns, policy, redaction


def _synth(prefix: str, body: str) -> str:
    """Assemble a secret-*shaped* fixture from parts.

    Some provider token shapes (Stripe ``sk_live_``/``rk_live_``, GitLab
    ``glpat-``) are recognised by GitHub secret-scanning *push protection*,
    which would block this test file from being pushed even though the
    values are synthetic. Concatenating prefix + body at runtime means no
    contiguous token literal ever appears in the source bytes the scanner
    sees, while ``redact`` still receives the identical assembled value.
    """
    return prefix + body


# --- Shape: tables compile and the executors consume them ---


def test_tables_compile_and_expose_required_names() -> None:
    assert isinstance(patterns.PATTERNS_VERSION, str) and patterns.PATTERNS_VERSION
    assert patterns.REDACTION_PLACEHOLDER == "[REDACTED]"
    assert isinstance(patterns.REDACTION_PREFIX_PATTERNS, tuple)
    assert isinstance(patterns.REDACTION_PATTERNS, tuple)
    assert all(
        isinstance(p, re.Pattern) and isinstance(r, str)
        for p, r in patterns.REDACTION_PREFIX_PATTERNS
    )
    assert all(isinstance(p, re.Pattern) for p in patterns.REDACTION_PATTERNS)
    for name in (
        "URL_CREDS_PATTERN",
        "MYSQL_FAMILY_CLI_PATTERN",
        "MYSQL_COMPACT_PASSWORD_PATTERN",
        "TIER2_PATTERN",
        "TIER3_PATTERN",
        "PRIV_ESC_PATTERN",
    ):
        assert isinstance(getattr(patterns, name), re.Pattern), name


def test_redaction_consumes_the_published_tables() -> None:
    # The executor must reach the same compiled objects, not a shadow copy.
    # `redact` reads through the module each call, so monkeypatching the
    # public name on `patterns` flows through to the public function.
    saw_called = False
    original = patterns.REDACTION_PREFIX_PATTERNS

    class _MarkerPattern:
        def sub(self, _repl: str, text: str) -> str:
            nonlocal saw_called
            saw_called = True
            return text

    try:
        patterns.REDACTION_PREFIX_PATTERNS = ((_MarkerPattern(), "x"),)  # type: ignore[misc]
        redaction.redact("nothing-secret-here")
    finally:
        patterns.REDACTION_PREFIX_PATTERNS = original  # type: ignore[misc]
    assert saw_called, "redact() did not consume patterns.REDACTION_PREFIX_PATTERNS"


def test_policy_consumes_the_published_tables() -> None:
    # Same idea for classify(): if we swap TIER3_PATTERN with one that
    # matches anything, every command should classify Tier 3.
    original = patterns.TIER3_PATTERN
    try:
        patterns.TIER3_PATTERN = re.compile(r".+")  # type: ignore[misc]
        assert policy.classify("shell_exec", "ls").name == "IRREVERSIBLE"
    finally:
        patterns.TIER3_PATTERN = original  # type: ignore[misc]


# --- Redaction: positive (catches the secret) + negative (does not over-scrub) ---


def test_authorization_header_positive_and_negative() -> None:
    # Positive: the `Authorization: <value>` form is redacted (the structure-
    # preserving pattern collapses the value to the placeholder).
    out = redaction.redact("Authorization: superSecret123")
    assert "superSecret123" not in out
    assert "Authorization:" in out  # prefix preserved
    # Negative: a literal "authorization" appearing in body text without
    # the `:`/`=` separator and a value must not be touched.
    assert "the authorization to act" in redaction.redact("he had the authorization to act")


def test_authorization_header_redacts_whole_bearer_value() -> None:
    # B-023 regression. The previous Authorization regex consumed only the
    # first whitespace-delimited token after `:`, so `Authorization: Bearer
    # <token>` collapsed to `Authorization: [REDACTED] <token>` and the
    # bearer value leaked into the audit log. The widened pattern must
    # consume the whole header value.
    out = redaction.redact("Authorization: Bearer abcdef123456")
    assert "abcdef123456" not in out
    assert "Bearer" not in out
    assert "Authorization:" in out


def test_authorization_header_value_stops_at_quote() -> None:
    # Quoted-CLI form: the redactor must stop at the closing quote so it
    # does not eat the next argv token. Assert the exact output shape so
    # the position of the redacted span and the position of the trailing
    # argv token are both unambiguous (substring-style assertions can
    # mask off-by-one bleed into the next token).
    out = redaction.redact('curl -H "Authorization: Bearer abc.def-ghi" trailing-arg')
    assert out == 'curl -H "Authorization: [REDACTED]" trailing-arg'


def test_authorization_header_handles_basic_auth() -> None:
    # Non-Bearer Authorization schemes (Basic, Digest, ...) must also be
    # redacted as a whole value, not just the first token.
    out = redaction.redact("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA" not in out
    assert "Basic" not in out
    assert "Authorization:" in out


def test_authorization_header_value_stops_at_newline() -> None:
    # Multi-header input on consecutive lines: redacting the auth header
    # must not bleed into the next header.
    out = redaction.redact("Authorization: Bearer abc\nHost: example.org")
    assert "abc" not in out
    assert "Host: example.org" in out


def test_authorization_header_does_not_hide_trailing_shell_suffix() -> None:
    # Regression for audit-integrity: bare `Authorization:` redaction must
    # not consume shell suffixes that are outside the header value.
    text = ": Authorization: cover && echo suffix-output"
    out = redaction.redact(text)
    assert out == ": Authorization: [REDACTED] && echo suffix-output"


def test_authorization_header_json_dict_form() -> None:
    # JSON shape (e.g. a Python `headers={"Authorization": "Bearer X"}`
    # passed verbatim through to the audit args). The prefix's optional
    # quote-around-key + quote-around-value lets the pattern reach the
    # value's closing quote without leaking.
    out = redaction.redact('{"Authorization": "Bearer abc.def-ghi"}')
    assert "Bearer" not in out
    assert "abc.def" not in out
    # Basic-auth variant: a base64 user:pass blob must not survive.
    out2 = redaction.redact('{"Authorization": "Basic dXNlcjpwYXNzd29yZA=="}')
    assert "dXNlcjpwYXNzd29yZA" not in out2
    assert "Basic" not in out2


def test_authorization_header_aws_sigv4() -> None:
    # AWS Signature v4 splits its value across commas:
    #   Authorization: AWS4-HMAC-SHA256 Credential=AKI..., SignedHeaders=..., Signature=<hex>
    # The Signature is the request-binding HMAC and IS a secret. Stopping
    # the redaction at the first comma would strand it. Pattern must
    # consume through commas to the end-of-line / closing quote.
    sigv4 = (
        "Authorization: AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"
    )
    out = redaction.redact(sigv4)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024" not in out
    assert "SignedHeaders" not in out  # whole value collapsed


def test_proxy_authorization_pinned() -> None:
    # The pattern explicitly covers `Proxy-Authorization`; pin it with a
    # test so a future narrowing of the prefix does not silently drop
    # this variant.
    out = redaction.redact("Proxy-Authorization: Bearer proxysecret123")
    assert "proxysecret123" not in out
    assert "Proxy-Authorization:" in out


def test_authorization_single_quoted_cli_form() -> None:
    # Some operators use single quotes in their shell:
    #   curl -H 'Authorization: Bearer X'
    # The value must stop at the closing single quote, not eat past it.
    # Equality assertion (rather than substring) so the position of the
    # trailing argv token is unambiguous.
    out = redaction.redact("curl -H 'Authorization: Bearer abc' trailing-arg")
    assert out == "curl -H 'Authorization: [REDACTED]' trailing-arg"


def test_bearer_positive_and_negative() -> None:
    # Positive: the entire token (including the hyphenated suffix) must be
    # scrubbed; assert against the full token, not just an interior
    # substring, so a regression that stopped at the hyphen would still
    # fail this test.
    out = redaction.redact("Bearer abc.def-ghi")
    assert "abc.def-ghi" not in out
    assert "abc.def" not in out
    assert "-ghi" not in out
    assert "[REDACTED]" in out
    # "Bearer" as a word with no following token must not turn the next
    # punctuation into a placeholder.
    assert "(bearer." in redaction.redact("the messenger (bearer.) arrived")


def test_keyvalue_positive_and_negative() -> None:
    assert "topsecret" not in redaction.redact("password: topsecret")
    # An unrelated word containing "secret" is preserved.
    assert "secretariat" in redaction.redact("the secretariat opened at 9")


def test_pem_block_positive_and_negative() -> None:
    blob = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
    out = redaction.redact(blob)
    assert "AAAA" not in out
    # Negative: an unrelated PEM-looking sentence is not redacted.
    assert "begin private investigation" in redaction.redact("we begin private investigation now")


def test_url_creds_positive_and_negative() -> None:
    assert "://[REDACTED]@" in redaction.redact("https://user:pass@host/repo.git")
    # Negative: a colon in the path or in a port spec is not credentials.
    assert "http://host:8080/path" in redaction.redact("http://host:8080/path")


def test_mysql_compact_password_gated_by_family() -> None:
    # Positive: -p inside a mysql command is redacted.
    assert "leaked" not in redaction.redact("mysql -uroot -pleaked db")
    # Negative: -p in ssh/nmap is NOT redacted (this is the whole point of
    # the family gate).
    assert "-p22" in redaction.redact("ssh -p22 user@host")
    assert "-p1-1000" in redaction.redact("nmap -p1-1000 host.example")


def test_provider_token_shapes_positive_and_negative() -> None:
    # Positive: each provider shape collapses to the placeholder; assert
    # against the full input token so a regression that captured a
    # partial prefix would leave evidence and fail the test.
    ghp_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    out = redaction.redact(ghp_token)
    assert ghp_token not in out
    assert "abcdefghij" not in out
    assert out == "[REDACTED]"
    akia_token = "AKIA0000000000000000"
    out = redaction.redact(akia_token)
    assert akia_token not in out
    assert out == "[REDACTED]"
    # Negative: a too-short look-alike does not trigger.
    assert "ghp_short" in redaction.redact("ghp_short")
    assert "AKIASHORT" in redaction.redact("AKIASHORT")


def test_openai_project_and_service_keys() -> None:
    # The bare `sk-[A-Za-z0-9]{16,}` shape missed the project / service /
    # admin prefixes because the internal hyphen broke the run. Each must
    # now collapse whole. Assert the full token is gone, not a fragment.
    for tok in (
        "sk-abcdefghijklmnopqrstuvwx",  # classic (unchanged behavior)
        "sk-proj-abcdefghijklmnopqrstuvwxyz1234",
        "sk-svcacct-abcdefghijklmnopqrstuvwxyz12",
        "sk-admin-abcdefghijklmnopqrstuvwxyz1234",
        # URL-safe opaque tail: the project/service body legitimately
        # contains `_` and `-`. A regression to an alnum-only tail would
        # stop at the first separator and leave the rest in the log.
        "sk-proj-abc_def-ghijklmnopqrstuvwxyz1234567890",
    ):
        out = redaction.redact(tok)
        assert tok not in out, tok
        assert out == "[REDACTED]", tok
    # Negative: a hyphenated identifier that merely starts `sk-` is not a
    # key (the run is broken by hyphens before the length floor is met).
    assert "sk-build-step" in redaction.redact("sk-build-step")


def test_google_secret_shapes_positive_and_negative() -> None:
    # Google API key (AIza + 35) and OAuth access token (ya29.<...>).
    api = "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
    assert redaction.redact(api) == "[REDACTED]"
    oauth = "ya29.A0ARrdaM-abcdefghijklmnop1234567890"
    out = redaction.redact(oauth)
    assert "A0ARrdaM" not in out
    assert "[REDACTED]" in out
    # ya29 tokens are opaque and carry additional dots in the body; the
    # whole token must collapse, not just the run up to the next dot.
    dotted = "ya29.A0ARrdaMabcdefghijklmnop.1234567890abcdefghijklmnop"
    out_dotted = redaction.redact(dotted)
    assert "1234567890abcdefghijklmnop" not in out_dotted
    assert out_dotted == "[REDACTED]"
    # Negative: the bare prefixes without a long value are left intact.
    assert "AIza" in redaction.redact("the AIza prefix alone")
    assert "ya29 release" in redaction.redact("ya29 release notes")


def test_stripe_keys_positive_and_negative() -> None:
    for tok in (
        _synth("sk_live_", "0123456789abcdefABCDEFgh"),
        _synth("sk_test_", "0123456789abcdefABCDEFgh"),
        _synth("rk_live_", "51HCs0123456789abcdefABCDEF"),
        # Over-long body: an upper bound would have left a tail. The run is
        # unbounded so even a 110-char value collapses whole.
        _synth("sk_live_", "A" * 110),
    ):
        assert redaction.redact(tok) == "[REDACTED]", tok
    # Negative: `pk_live_` (publishable, not secret) and a non-Stripe
    # `sk_` word are not in scope; the env qualifier is required.
    assert "sk_local_thing" in redaction.redact("sk_local_thing")


def test_registry_and_jwt_shapes_positive_and_negative() -> None:
    # GitLab PAT, npm token, PyPI upload token.
    assert redaction.redact(_synth("glpat-", "ABCDEF1234567890abcd")) == "[REDACTED]"
    assert redaction.redact("npm_abcdefghijklmnopqrstuvwxyz0123456789") == "[REDACTED]"
    # Longer-than-reference npm token still collapses whole (unbounded body).
    assert redaction.redact("npm_" + "a" * 44) == "[REDACTED]"
    pypi = "pypi-AgEIcHlwaS5vcmcCABCDEFxyz1234567890abcd"
    assert redaction.redact(pypi) == "[REDACTED]"
    # JWT: header.payload.signature; both leading segments start `ey`.
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
    out = redaction.redact(jwt)
    assert "eyJzdWIiOiIxMjM0NTY3ODkwIn0" not in out
    assert "[REDACTED]" in out
    # Compact JWT with a small claim set: the payload segment is short
    # (`{"sub":"1"}`) but the token is still a bearer credential and must
    # be redacted (the header floor is the anchor, not the payload length).
    compact = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N"
    out_compact = redaction.redact(compact)
    assert "eyJzdWIiOiIxIn0" not in out_compact
    assert "[REDACTED]" in out_compact
    # Negatives: short look-alikes / a dotted version string do not trigger.
    assert "glpat-short" in redaction.redact("glpat-short")
    assert "app.eyeball.v2" in redaction.redact("app.eyeball.v2")


def test_anthropic_and_huggingface_shapes_positive_and_negative() -> None:
    # AI-provider tokens that arrive bare in command args (audit pass
    # 2026-06-21, SEC-4). Built via _synth so the synthetic fixtures do not
    # trip secret-scanning push protection; assert the full token is gone.
    for tok in (
        # Anthropic: the `sk-ant-` hyphens break the bare `sk-<alnum>` run, so
        # this needs its own rule; the opaque body (URL-safe `_`/`-`) collapses
        # whole rather than stopping at the first separator.
        _synth("sk-ant-api03-", "abcdefghij_klmnopqrst-uvwxyz0123456789ABCD"),
        _synth("sk-ant-admin01-", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        # HuggingFace user access token (`hf_` + >=34 alnum); unbounded body.
        _synth("hf_", "a" * 34),
        _synth("hf_", "Z" * 50),
    ):
        assert redaction.redact(tok) == "[REDACTED]", tok
    # Negatives: short look-alikes stay intact (length floor not met).
    assert "sk-ant-tier" in redaction.redact("sk-ant-tier list")
    assert "hf_short" in redaction.redact("hf_short")


# --- Policy: positive (classifies high) + negative (near-miss stays low) ---


def test_tier3_positive_and_negative() -> None:
    assert policy.classify("shell_exec", "rm -rf /tmp/x").name == "IRREVERSIBLE"
    assert policy.classify("shell_exec", "shutdown -h now").name == "IRREVERSIBLE"
    # Negative: the heuristic's start is anchored with `(?<![\w])`, so an
    # embedded substring with a word char before "shutdown" does not match.
    # (Note: the heuristic IS intentionally conservative for boundary-adjacent
    # forms like "graceful-shutdown.md" — `-` is a non-word char so the anchor
    # still fires there - so do not over-narrow this test.)
    assert policy.classify("shell_exec", "echo theshutdown").name == "REVERSIBLE"


def test_tier2_positive_and_negative() -> None:
    assert policy.classify("shell_exec", "systemctl restart nginx").name == "STATEFUL"
    assert policy.classify("shell_exec", "apt-get install foo").name == "STATEFUL"
    # Negative: `systemctl status` (read-only) is not Tier 2.
    assert policy.classify("shell_exec", "systemctl status nginx").name == "REVERSIBLE"


def test_priv_esc_positive_and_negative() -> None:
    assert policy.classify("shell_exec", "sudo ls /root").name == "STATEFUL"
    assert policy.classify("shell_exec", "doas ls /root").name == "STATEFUL"
    # Negative: "sudoku" must not match `\bsudo\b`.
    assert policy.classify("shell_exec", "echo sudoku-fan").name == "REVERSIBLE"


def test_tier_anchor_catches_nonword_start_alternatives() -> None:
    # POL-1 (adversarial audit): the classification anchor must let alternatives
    # that begin with a non-word char (> / :) fire. The old leading `\b` made
    # them dead code, so disk-wipe-by-redirect, the fork bomb, and >/etc/ writes
    # classified Tier 1 and were admitted in guarded mode.
    from relay_shell.policy import Tier, classify

    assert classify("shell_exec", "> /dev/sda") == Tier.IRREVERSIBLE
    assert classify("shell_exec", "cat /dev/zero > /dev/sda") == Tier.IRREVERSIBLE
    assert classify("shell_exec", ":(){ :|:& };:") == Tier.IRREVERSIBLE
    assert classify("shell_exec", "echo x >> /etc/passwd") == Tier.STATEFUL
    assert classify("shell_exec", "echo x > /etc/sudoers") == Tier.STATEFUL
    # Controls still classify high.
    assert classify("shell_exec", "rm -rf /") == Tier.IRREVERSIBLE
    assert classify("shell_exec", "dd if=/dev/zero of=/dev/sda") == Tier.IRREVERSIBLE
    assert classify("shell_exec", "systemctl restart nginx") == Tier.STATEFUL
    # No new false positives where the verb is only a substring.
    assert classify("shell_exec", "echo hello > /dev/null") == Tier.REVERSIBLE
    assert classify("shell_exec", "charm install foo") == Tier.REVERSIBLE
    assert classify("shell_exec", "ls -la") == Tier.REVERSIBLE


def test_redaction_compound_keyword_assignments() -> None:
    # RED-1 (adversarial audit): a secret keyword that is the suffix of a
    # compound name (DB_PASSWORD=, APP_SECRET=, API_TOKEN=) is preceded by `_`,
    # so the old `\b`-anchored prefix pattern never fired and the value leaked
    # into the audit log. The trailing `\s*[:=]\s*\S+` still gates it.
    for c in (
        "export DB_PASSWORD=prod-p@ss",
        "docker run -e API_TOKEN=abc123xyz svc",
        "REDIS_PASSWORD=hunter2",
        "myapp_secret=topsecret",
    ):
        out = redaction.redact(c)
        assert "[REDACTED]" in out, c
    joined = " ".join(
        redaction.redact(c)
        for c in (
            "export DB_PASSWORD=prod-p@ss",
            "API_TOKEN=abc123xyz",
            "REDIS_PASSWORD=hunter2",
            "myapp_secret=topsecret",
        )
    )
    for leaked in ("prod-p@ss", "abc123xyz", "hunter2", "topsecret"):
        assert leaked not in joined, leaked
    # Negative: ordinary key=value args are not over-redacted.
    for c in ("description=hello", "ls --color=auto", "filename=report.csv", "count=42"):
        assert "[REDACTED]" not in redaction.redact(c), c


def test_pem_redaction_matches_and_is_redos_bounded() -> None:
    import time

    # Still redacts a real PEM private-key block.
    key = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIBdummy" * 40 + "\n-----END RSA PRIVATE KEY-----"
    assert redaction.redact(key) == "[REDACTED]"
    # RED-2: many unterminated BEGIN markers must not drive O(n^2) backtracking
    # on the synchronous audit redaction path. The length-bounded matcher keeps
    # it linear; the generous guard catches an O(n^2) regression (this input was
    # ~7.6s before the fix, ~1s after).
    blob = "-----BEGIN PRIVATE KEY-----\n" * 6400
    t0 = time.perf_counter()
    out = redaction.redact(blob)
    assert time.perf_counter() - t0 < 5.0
    assert "[REDACTED]" not in out  # no closing END -> no match
