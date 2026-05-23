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
:mod:`relay_shell.patterns` so a security reviewer can audit "added a
pattern" as a one-file diff.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

from . import patterns

__all__ = ["Policy", "PolicyDecision", "Tier", "classify"]


class Tier(IntEnum):
    READ_ONLY = 0
    REVERSIBLE = 1
    STATEFUL = 2
    IRREVERSIBLE = 3


# Tools that never mutate local/remote state.
# Note: ssh_keyscan is NOT here. It opens caller-chosen outbound TCP
# connections (SSRF-shaped surface to whatever the relay can reach,
# including private/cloud-metadata ranges) and leaves entries in
# remote sshd logs. That puts it outside the "observation-only client"
# contract of `readonly` mode. classify() falls through to Tier 1
# (REVERSIBLE) for ssh_keyscan, which keeps it permitted in `open` and
# in `guarded` (Tier 1 < Tier 2) but rejected in `readonly`.
_READ_ONLY_TOOLS = frozenset(
    {
        "server_info",
        "ssh_hosts",
        "ssh_check",
        "session_list",
        "session_recv",
        "ssh_forward_list",
        "audit_tail",
    }
)

# Tools whose primary effect is to change remote/local state.
_MUTATING_TOOLS = frozenset({"ssh_upload", "ssh_download", "ssh_forward"})


def classify(tool: str, command: str = "") -> Tier:
    """Best-effort tier for ``tool`` given an optional command string.

    Conservative: when in doubt it returns the *higher* tier. Classification
    is advisory in ``open`` mode and enforced in the stricter modes.
    """
    if tool in _READ_ONLY_TOOLS:
        return Tier.READ_ONLY
    text = command or ""
    if patterns.TIER3_PATTERN.search(text):
        return Tier.IRREVERSIBLE
    if patterns.PRIV_ESC_PATTERN.search(text):
        return Tier.STATEFUL
    if patterns.TIER2_PATTERN.search(text):
        return Tier.STATEFUL
    if tool in _MUTATING_TOOLS:
        return Tier.STATEFUL
    if tool in {
        "shell_exec",
        "shell_script",
        "ssh_exec",
        "ssh_fanout",
        "shell_spawn",
        "ssh_spawn",
    }:
        # An interactive shell or arbitrary command with no obvious mutating
        # token: treat as reversible-by-default but never read-only.
        # ssh_fanout is the multi-host variant of ssh_exec - the TIER
        # heuristics above already escalate (rm -rf, systemctl restart,
        # ...) based on the command itself before we reach this branch.
        return Tier.REVERSIBLE
    if tool in {"session_send", "session_kill", "session_resize"}:
        return Tier.REVERSIBLE
    return Tier.REVERSIBLE


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    tier: Tier
    reason: str


class Policy:
    """Admits or refuses a call based on tier and configured mode."""

    def __init__(self, mode: str, deny: str = "", allow: str = "") -> None:
        self.mode = mode
        self._deny = re.compile(deny) if deny else None
        self._allow = re.compile(allow) if allow else None

    def check(self, tool: str, command: str = "") -> PolicyDecision:
        tier = classify(tool, command)
        probe = f"{tool} {command}".strip()

        if self._deny is not None and self._deny.search(probe):
            return PolicyDecision(False, tier, "matched RELAY_SHELL_POLICY_DENY")

        if self.mode == "readonly" and tier != Tier.READ_ONLY:
            return PolicyDecision(
                False, tier, f"readonly mode refuses Tier {int(tier)} ({tier.name})"
            )

        if self.mode == "guarded" and tier >= Tier.STATEFUL:
            if self._allow is not None and self._allow.search(probe):
                return PolicyDecision(True, tier, "guarded: allowed by RELAY_SHELL_POLICY_ALLOW")
            return PolicyDecision(
                False,
                tier,
                f"guarded mode refuses Tier {int(tier)} ({tier.name}) "
                f"without an RELAY_SHELL_POLICY_ALLOW match",
            )

        return PolicyDecision(True, tier, "permitted")
