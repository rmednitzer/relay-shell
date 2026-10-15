from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from relay_shell.util import clamp, gen_id, now_iso, sha256_hex, truncate


def test_clamp() -> None:
    assert clamp(5, 1, 10) == 5
    assert clamp(-1, 1, 10) == 1
    assert clamp(99, 1, 10) == 10
    assert clamp(5, 10, 1) == 5  # tolerant of swapped bounds


def test_sha256_hex_stable() -> None:
    assert sha256_hex("abc") == sha256_hex(b"abc")
    assert len(sha256_hex("x")) == 64


def test_truncate_marks_and_bounds() -> None:
    text = "a" * 100
    out = truncate(text, 10)
    assert out.startswith("a" * 10)
    assert "TRUNCATED" in out
    assert truncate("short", 100) == "short"


def test_truncate_is_byte_safe() -> None:
    out = truncate("é" * 50, 5)  # multi-byte
    assert "TRUNCATED" in out
    out.encode("utf-8")  # must not raise


def test_now_iso_has_offset() -> None:
    assert "T" in now_iso()
    assert now_iso().endswith("+00:00")


def test_gen_id_unique() -> None:
    assert gen_id("sh") != gen_id("sh")
    assert gen_id("sh").startswith("sh-")


# --- property tests for truncate ------------------------------------------
#
# `truncate` underpins the output cap on every tool. These properties hold for any
# input the executor might produce (multi-byte glyphs, surrogate-free unicode,
# pathological repeats). `max_examples` stays modest so the default run takes
# under a second; deeper sweeps belong in `tests/test_fuzz.py`.

_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    min_size=0,
    max_size=512,
)
_LIMIT = st.integers(min_value=1, max_value=4096)


@settings(max_examples=300, deadline=None)
@given(_TEXT, _LIMIT)
def test_truncate_output_is_valid_utf8(text: str, limit: int) -> None:
    # Splitting a multi-byte sequence must not leave a dangling lead byte, which
    # would corrupt every consumer (audit hash, wire protocol).
    out = truncate(text, limit)
    out.encode("utf-8")  # must not raise


@settings(max_examples=300, deadline=None)
@given(_TEXT, _LIMIT)
def test_truncate_passthrough_when_under_limit(text: str, limit: int) -> None:
    # Input within the byte budget comes back verbatim (no marker). The runner
    # relies on this for exact-output assertions (audit_tail, ssh_check probes).
    raw = text.encode("utf-8", "replace")
    if len(raw) <= limit:
        assert truncate(text, limit) == text


@settings(max_examples=300, deadline=None)
@given(_TEXT, _LIMIT)
def test_truncate_marks_when_over_limit(text: str, limit: int) -> None:
    # The marker lets callers and audit readers tell the output is partial.
    raw = text.encode("utf-8", "replace")
    out = truncate(text, limit)
    if len(raw) > limit:
        assert "TRUNCATED" in out
        assert str(len(raw)) in out
        assert str(limit) in out


@settings(max_examples=300, deadline=None)
@given(_TEXT, _LIMIT)
def test_truncate_head_is_prefix_of_input(text: str, limit: int) -> None:
    # The kept head must be a real prefix of the input. Compared as UTF-8 bytes
    # because `truncate` re-decodes with errors="replace", which can collapse a
    # split multi-byte sequence into U+FFFD.
    raw = text.encode("utf-8", "replace")
    out = truncate(text, limit)
    if len(raw) > limit:
        head = out.split("\n\n[TRUNCATED")[0]
        head_bytes = head.encode("utf-8", "replace")
        # A clean prefix, or one whose final char became U+FFFD (3 bytes).
        assert len(head_bytes) <= limit + 3
