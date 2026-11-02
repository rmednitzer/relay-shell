"""Equivalent scan gates: classification and privilege semantics stay unchanged."""

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from relay_shell import patterns, policy


@pytest.mark.parametrize("space", [" ", "\t", "\n", "\r\n", "\u00a0", "\u2003"])
@pytest.mark.parametrize(
    "words",
    [
        ["rm", "-rf", "/tmp/example"],
        ["rm", "file", "--force"],
        ["rm", "--no-preserve-root", "file"],
        ["Remove-Item", "file", "-Recurse"],
        ["Remove-Item", "file", "-Force"],
        ["del", "file", "/s"],
        ["rmdir", "file", "/q"],
        ["format", "/q", "C:"],
        ["rm", "file"],
        ["Remove-Item", "file"],
        ["format", "table"],
    ],
)
def test_gated_family_matches_reference(space: str, words: list[str]) -> None:
    text = space.join(words)
    assert patterns.matches_tier3(text) == bool(patterns.TIER3_PATTERN.search(text))
    assert patterns.matches_tier2(text) == bool(patterns.TIER2_PATTERN.search(text))


@pytest.mark.fuzz
@settings(max_examples=1000, deadline=None)
@given(
    st.lists(
        st.sampled_from(
            [
                "rm",
                "Remove-Item",
                "del",
                "format",
                "-rf",
                "--force",
                "-Recurse",
                "/s",
                "C:",
                "sudo",
                "\u017fudo",
                "echo",
                "grep",
                "exec",
                "sh",
                "-c",
                "reboot",
                "file",
                ";",
                "|",
                "(",
                ")",
                "'",
                '"',
                "\\",
                "a=b",
            ]
        ),
        min_size=0,
        max_size=40,
    ),
    st.sampled_from([" ", "\t", "\n", "\u00a0", "\u2003"]),
)
def test_full_assessment_matches_ungated_reference(words: list[str], space: str) -> None:
    text = policy._strip_line_continuations(space.join(words))
    if patterns.TIER3_PATTERN.search(text):
        expected = policy.Tier.IRREVERSIBLE
    else:
        priv_text = (
            text
            if patterns.PRIV_ESC_EVAL_HINT.search(text)
            else patterns.PRIV_ESC_READER_SEGMENT.sub(" ", text)
        )
        if patterns.PRIV_ESC_PATTERN.search(priv_text) or patterns.TIER2_PATTERN.search(text):
            expected = policy.Tier.STATEFUL
        else:
            expected = policy.Tier.REVERSIBLE
    assert policy.classify("shell_exec", space.join(words)) == expected


@pytest.mark.fuzz
@settings(max_examples=1000, deadline=None)
@given(st.text(max_size=300))
def test_gates_preserve_unicode_regex_language(text: str) -> None:
    assert patterns.matches_tier3(text) == bool(patterns.TIER3_PATTERN.search(text))
    assert patterns.matches_tier2(text) == bool(patterns.TIER2_PATTERN.search(text))


def test_replaced_tier2_table_remains_authoritative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(patterns, "TIER2_PATTERN", re.compile(r".+"))
    assert policy.classify("shell_exec", "ls") == policy.Tier.STATEFUL
