"""Hypothesis-driven property tests for `redact` and `classify`.

These run nightly only (the default `pytest` invocation deselects the
``fuzz`` marker via `pyproject.toml`'s `addopts`). The suite asserts
invariants the security-sensitive primitives must hold for *any*
input, not just the hand-picked cases in `test_patterns.py`,
`test_redaction.py`, and `test_policy.py`.

Run locally with::

    pytest -m fuzz

The nightly workflow (`.github/workflows/nightly-fuzz.yml`) bumps
`max_examples` via the `HYPOTHESIS_PROFILE=ci` profile.
"""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from relay_shell import patterns
from relay_shell.policy import Tier, classify
from relay_shell.redaction import redact, redact_args

# --- profiles ---------------------------------------------------------------
#
# Local / PR runs (when fuzz is opted-in) use a small example budget so the
# loop stays fast. Nightly CI sets HYPOTHESIS_PROFILE=ci to amplify it.

settings.register_profile("default", max_examples=100, deadline=None)
settings.register_profile(
    "ci",
    max_examples=5000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

pytestmark = pytest.mark.fuzz


# Strategy: arbitrary unicode text up to ~256 chars. Mostly excludes
# control characters that would generate huge volumes of unreadable cases;
# the regex tables are byte-oriented and don't care about glyph rendering.
_TEXT = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),  # surrogates
        blacklist_characters=("\x00",),  # NUL would break some pattern dumps
    ),
    min_size=0,
    max_size=256,
)

# Subset: printable ASCII so we can mix in real secret shapes deterministically.
_PRINTABLE = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126),
    min_size=0,
    max_size=256,
)


# --- redact: universal properties ------------------------------------------


@given(_TEXT)
def test_redact_never_raises(s: str) -> None:
    redact(s)  # only asserting no exception escapes


@given(_TEXT)
def test_redact_is_idempotent(s: str) -> None:
    once = redact(s)
    twice = redact(once)
    assert once == twice


@given(_TEXT)
def test_redact_preserves_when_no_secret_shape(s: str) -> None:
    # If the input does not match any pattern, redact() must leave it
    # alone. We probe by checking that the round-trip is fixed-point
    # AND that the placeholder is not present (covers both directions).
    out = redact(s)
    if patterns.REDACTION_PLACEHOLDER not in out:
        assert out == s


# --- redact: shape-targeted properties -------------------------------------
#
# For each known secret shape, generate a *distinctive* marker (so we can
# tell whether the original survived even when surrounding text overlaps),
# embed it in the relevant syntax, and assert: (1) the placeholder appears
# in the output, AND (2) the marker doesn't survive. The shapes match the
# patterns in `src/relay_shell/patterns.py`; the marker is namespaced
# (``FUZZSECRET-<n>``) so we never collide with whatever hypothesis is
# putting in the surrounding text strategies.


def _marker(nonce: int) -> str:
    # A token shape that satisfies every value class in the redaction
    # patterns (alphanumeric + `-`, length >= 16) and is unmistakable in
    # the output so we can prove the marker didn't survive.
    return f"FUZZSECRET-{nonce:020d}"


@st.composite
def _safe_surround(draw) -> tuple[str, str]:
    """Generate before/after surrounding text that cannot contain the marker."""
    before = draw(_PRINTABLE)
    after = draw(_PRINTABLE)
    # The marker prefix `FUZZSECRET-` is rare enough in random text; assert
    # the marker cannot accidentally appear in surrounds by stripping it.
    before = before.replace("FUZZSECRET", "").replace("\r", "").replace("\n", "")
    after = after.replace("FUZZSECRET", "").replace("\r", "").replace("\n", "")
    return before, after


@given(
    nonce=st.integers(min_value=0, max_value=10**18),
    surround=_safe_surround(),
)
def test_redact_kills_bearer_token(nonce: int, surround: tuple[str, str]) -> None:
    # `Bearer <token>` in an HTTP header / log line. The token uses the
    # marker shape so we can verify it does not survive even if the
    # surrounds happen to contain similar-looking text.
    token = _marker(nonce)
    before, after = surround
    payload = f"{before}Authorization: Bearer {token}{after}"
    out = redact(payload)
    assert patterns.REDACTION_PLACEHOLDER in out
    assert token not in out, f"bearer token survived redaction: {token!r} -> {out!r}"


@given(
    nonce=st.integers(min_value=0, max_value=10**18),
)
def test_redact_kills_url_creds(nonce: int) -> None:
    # `https://user:<password>@host/...`. We construct the host from a
    # disjoint alphabet so the password marker cannot accidentally appear
    # there. The password marker shape avoids URL-reserved chars.
    pw = _marker(nonce)
    payload = f"https://user:{pw}@disjoint.example.com/path"
    out = redact(payload)
    assert patterns.REDACTION_PLACEHOLDER in out
    assert pw not in out, f"URL password survived redaction: {pw!r} -> {out!r}"


@given(
    nonce=st.integers(min_value=0, max_value=10**18),
    flag=st.sampled_from(["--token", "--api-key", "--password", "-token", "-password"]),
    sep=st.sampled_from(["=", " "]),
)
def test_redact_kills_cli_flag(nonce: int, flag: str, sep: str) -> None:
    # CLI-style flags accept both `--token=value` and `--token value`. Bare
    # `token value` (no dash) is intentionally not covered (would over-scrub
    # `echo token foo`); see redaction.py docstring for scope.
    secret = _marker(nonce)
    shape = f"{flag}{sep}{secret}"
    out = redact(shape)
    assert patterns.REDACTION_PLACEHOLDER in out, f"placeholder missing in {shape!r} -> {out!r}"
    assert secret not in out, f"secret survived in {shape!r}: {secret!r} -> {out!r}"


@given(
    nonce=st.integers(min_value=0, max_value=10**18),
    keyword=st.sampled_from(["token", "api_key", "api-key", "password", "secret"]),
    sep=st.sampled_from([":", "="]),
)
def test_redact_kills_kv_pair(nonce: int, keyword: str, sep: str) -> None:
    # `keyword=value` / `keyword:value` (with or without surrounding
    # whitespace) is the inline-credentials shape - this is what the
    # `token`/`api_key`/`password` prefix pattern catches.
    secret = _marker(nonce)
    shape = f"{keyword}{sep} {secret}"
    out = redact(shape)
    assert patterns.REDACTION_PLACEHOLDER in out, f"placeholder missing in {shape!r} -> {out!r}"
    assert secret not in out, f"secret survived in {shape!r}: {secret!r} -> {out!r}"


# --- redact_args: structural properties -------------------------------------


@st.composite
def _scalar_or_str(draw) -> object:
    return draw(
        st.one_of(
            _PRINTABLE,
            st.integers(),
            st.booleans(),
            st.none(),
            st.floats(allow_nan=False, allow_infinity=False),
        )
    )


@given(
    st.dictionaries(
        keys=st.text(min_size=1, max_size=12),
        values=_scalar_or_str(),
        min_size=0,
        max_size=10,
    )
)
def test_redact_args_preserves_keyset(args: dict) -> None:
    out = redact_args(args)
    assert set(out.keys()) == set(args.keys())


@given(
    st.dictionaries(
        keys=st.text(min_size=1, max_size=12),
        values=_PRINTABLE,
        min_size=0,
        max_size=10,
    )
)
def test_redact_args_string_values_idempotent(args: dict[str, str]) -> None:
    once = redact_args(args)
    twice = redact_args(once)
    assert once == twice


# --- classify: total + bounded ---------------------------------------------


@given(
    tool=st.text(min_size=1, max_size=20),
    command=_TEXT,
)
def test_classify_never_raises(tool: str, command: str) -> None:
    tier = classify(tool, command)
    assert isinstance(tier, Tier)


@given(_TEXT)
def test_classify_tier3_escalates_regardless_of_command_prefix(prefix: str) -> None:
    # Adding any prefix in front of an unambiguous Tier-3 keyword must not
    # downgrade the decision: a Tier-3 substring anywhere in the command
    # is enough to escalate.
    cmd = f"{prefix} rm -rf /"
    tier = classify("shell_exec", cmd)
    assert tier is Tier.IRREVERSIBLE, f"expected IRREVERSIBLE, got {tier} for cmd={cmd!r}"


@given(_TEXT)
def test_classify_random_text_is_at_most_reversible_for_shell_tools(text: str) -> None:
    # Without any tier-2/3 keyword or privilege-escalation token, a random
    # blob given to shell_exec must be classified at most as REVERSIBLE.
    # If hypothesis happens to generate a tier-escalating substring,
    # accept that as a valid escalation - we only assert *no spurious
    # downgrade* below.
    tier = classify("shell_exec", text)
    has_tier3 = bool(patterns.TIER3_PATTERN.search(text))
    has_tier2 = bool(patterns.TIER2_PATTERN.search(text))
    has_priv = bool(patterns.PRIV_ESC_PATTERN.search(text))
    if not (has_tier3 or has_tier2 or has_priv):
        assert tier is Tier.REVERSIBLE, (
            f"expected REVERSIBLE for tag-free shell_exec text, got {tier} for {text!r}"
        )


@given(_TEXT)
def test_classify_readonly_tools_stay_tier_zero(text: str) -> None:
    # Read-only tools are identified by name; command text does not
    # influence their tier. Cover the same surface for every name in
    # the public read-only set.
    for tool in ("server_info", "ssh_hosts", "ssh_check", "session_list", "audit_tail"):
        tier = classify(tool, text)
        assert tier is Tier.READ_ONLY, f"{tool} escaped tier 0 with command={text!r}"
