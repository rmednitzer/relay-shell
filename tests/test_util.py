from __future__ import annotations

from relay_shell.util import clamp, gen_id, now_iso, sha256_hex, truncate, utf8_len


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


def test_utf8_len() -> None:
    assert utf8_len("a") == 1
    assert utf8_len("é") == 2


def test_gen_id_unique() -> None:
    assert gen_id("sh") != gen_id("sh")
    assert gen_id("sh").startswith("sh-")
