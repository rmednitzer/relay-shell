"""Tiered-authority policy layer.

Every tool call is classified into a tier and then admitted or refused
according to the configured mode. This is *defence in depth*, not a sandbox:
with ``open`` mode (the default, documented posture) everything is permitted
but still classified and audited; ``guarded`` and ``readonly`` progressively
narrow the envelope so a persuaded model cannot exceed it.

Tiers (see docs/adr/0003-tiered-authority.md):

* Tier 0  read-only / observe         (no state change)
* Tier 1  reversible / low blast      (trivially undone)
* Tier 2  stateful / visible impact   (a user or dependent would notice)
* Tier 3  irreversible / high blast   (rollback expensive or impossible)

The deny list is enforced first in *every* mode, including ``open``.

The compiled regex tables (Tier 2 / Tier 3 / privilege escalation) live in
:mod:`relay_shell.patterns`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

from . import patterns

__all__ = ["Assessment", "Policy", "PolicyDecision", "Tier", "assess", "classify"]


class Tier(IntEnum):
    READ_ONLY = 0
    REVERSIBLE = 1
    STATEFUL = 2
    IRREVERSIBLE = 3


# Tools that never mutate local/remote state. `ssh_check` is here for inventory hosts
# only: probing a host outside the inventory dials a caller-chosen address with the
# relay's keys, so the `ssh_check` wrapper raises it to Tier 1 via `min_tier`.
#
# ssh_keyscan is NOT here. It opens caller-chosen outbound TCP connections
# (SSRF-shaped, reaching private/cloud-metadata ranges) and leaves entries in
# remote sshd logs, which is outside the observation-only contract of `readonly`.
# It falls through to Tier 1: permitted in `open` and `guarded`, rejected in
# `readonly`.
#
# operation_confirm is here: it only arms an ephemeral, single-use token in the
# in-memory broker (ADR 0009) and authorizes nothing by itself; the retried
# Tier-3 call is re-classified and re-admitted from scratch. Tier 0 keeps the
# step available in every mode (in readonly a Tier-3 op is refused regardless,
# so arming is a no-op).
_READ_ONLY_TOOLS = frozenset(
    {
        "server_info",
        "ssh_hosts",
        "ssh_check",
        "session_list",
        "session_recv",
        "ssh_forward_list",
        "audit_tail",
        "operation_confirm",
    }
)

# Tools whose primary effect is to change remote/local state.
_MUTATING_TOOLS = frozenset({"ssh_upload", "ssh_download", "ssh_forward"})


_CONTINUATIONS = frozenset({"\\\n", "\\\r\n"})


def _strip_line_continuations(text: str) -> str:
    """Delete shell line continuations (``\\<newline>``) outside single quotes.

    The shell removes them before parsing, so ``rm \\<nl>-rf /x`` is ``rm -rf /x`` and
    ``r\\<nl>m`` is ``rm``; inside single quotes the pair is literal text and is kept
    (``printf 'r\\<nl>m'`` prints it). Here-document bodies are not tracked.
    """
    if "\\\n" not in text and "\\\r\n" not in text:
        return text
    return patterns.LINE_CONTINUATION_PATTERN.sub(
        lambda m: "" if m.group(0) in _CONTINUATIONS else m.group(0), text
    )


# Why a call got its tier. Stable short strings: they are shown to the caller in a notice
# and keyed on by tests, so change them deliberately.
BASIS_READ_ONLY = "read-only tool"
BASIS_IRREVERSIBLE = "matched an irreversible-operation pattern"
BASIS_PRIVILEGE = "matched a privilege-escalation pattern"
BASIS_STATEFUL = "matched a state-changing pattern"
BASIS_MUTATING_TOOL = "the tool changes local or remote state"
BASIS_DEFAULT = "arbitrary command with no state-changing pattern"


@dataclass(frozen=True)
class Assessment:
    tier: Tier
    basis: str


def assess(tool: str, command: str = "") -> Assessment:
    """Best-effort tier for ``tool`` given an optional command string, with its basis.

    Conservative: when in doubt it returns the *higher* tier. Classification
    is advisory in ``open`` mode and enforced in the stricter modes. It is a regex
    heuristic over the command text, not a parse of the shell language.
    """
    if tool in _READ_ONLY_TOOLS:
        return Assessment(Tier.READ_ONLY, BASIS_READ_ONLY)
    text = _strip_line_continuations(command or "")
    if patterns.TIER3_PATTERN.search(text):
        return Assessment(Tier.IRREVERSIBLE, BASIS_IRREVERSIBLE)
    # A privilege wrapper named only by a read-only command is data, unless the line can
    # evaluate text (`echo 'sudo ...' | sh`), in which case it is still scanned.
    priv_text = (
        text
        if patterns.PRIV_ESC_EVAL_HINT.search(text)
        else patterns.PRIV_ESC_READER_SEGMENT.sub(" ", text)
    )
    if patterns.PRIV_ESC_PATTERN.search(priv_text):
        return Assessment(Tier.STATEFUL, BASIS_PRIVILEGE)
    if patterns.TIER2_PATTERN.search(text):
        return Assessment(Tier.STATEFUL, BASIS_STATEFUL)
    if tool in _MUTATING_TOOLS:
        return Assessment(Tier.STATEFUL, BASIS_MUTATING_TOOL)
    # Anything else (shell_exec/script/spawn, ssh_exec/fanout/spawn, session_send/
    # kill/resize) with no mutating token: Tier 1, never read-only.
    return Assessment(Tier.REVERSIBLE, BASIS_DEFAULT)


def classify(tool: str, command: str = "") -> Tier:
    """Best-effort tier for ``tool`` given an optional command string (see :func:`assess`)."""
    return assess(tool, command).tier


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    tier: Tier
    reason: str
    basis: str = ""  # why the tier was chosen (one of the BASIS_* strings)


class Policy:
    """Admits or refuses a call based on tier and configured mode."""

    def __init__(self, mode: str, deny: str = "", allow: str = "") -> None:
        self.mode = mode
        self._deny = re.compile(deny) if deny else None
        self._allow = re.compile(allow) if allow else None

    def check(
        self, tool: str, command: str = "", min_tier: Tier = Tier.READ_ONLY
    ) -> PolicyDecision:
        """Admit or refuse. ``min_tier`` raises the tier a caller knows is warranted
        but the text cannot show (for example a probe of a host outside the inventory)."""
        assessment = assess(tool, command)
        tier = max(assessment.tier, min_tier)
        basis = assessment.basis
        if min_tier > assessment.tier:
            basis = "raised by the tool (a target the command text does not show)"
        probe = f"{tool} {command}".strip()

        if self._deny is not None and self._deny.search(probe):
            return PolicyDecision(False, tier, "matched RELAY_SHELL_POLICY_DENY", basis)

        if self.mode == "readonly" and tier != Tier.READ_ONLY:
            return PolicyDecision(
                False, tier, f"readonly mode refuses Tier {int(tier)} ({tier.name})", basis
            )

        if self.mode == "guarded" and tier >= Tier.STATEFUL:
            if self._allow is not None and self._allow.search(probe):
                return PolicyDecision(
                    True, tier, "guarded: allowed by RELAY_SHELL_POLICY_ALLOW", basis
                )
            return PolicyDecision(
                False,
                tier,
                f"guarded mode refuses Tier {int(tier)} ({tier.name}) "
                f"without an RELAY_SHELL_POLICY_ALLOW match",
                basis,
            )

        return PolicyDecision(True, tier, "permitted", basis)
