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


def test_bearer_positive_and_negative() -> None:
    assert "abc.def" not in redaction.redact("Bearer abc.def-ghi")
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
    # Positive: each provider shape is caught.
    assert "abcdefghij" not in redaction.redact("ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert "AKIA0000000000000000" not in redaction.redact("AKIA0000000000000000")
    # Negative: a too-short look-alike does not trigger.
    assert "ghp_short" in redaction.redact("ghp_short")
    assert "AKIASHORT" in redaction.redact("AKIASHORT")


# --- Policy: positive (classifies high) + negative (near-miss stays low) ---


def test_tier3_positive_and_negative() -> None:
    assert policy.classify("shell_exec", "rm -rf /tmp/x").name == "IRREVERSIBLE"
    assert policy.classify("shell_exec", "shutdown -h now").name == "IRREVERSIBLE"
    # Negative: the heuristic is bounded by `\b` at the start, so an
    # embedded substring with no word boundary before "shutdown" does not
    # match. (Note: the heuristic IS intentionally conservative for
    # boundary-adjacent forms like "graceful-shutdown.md" — `-` is a word
    # boundary in regex - so do not over-narrow this test.)
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
