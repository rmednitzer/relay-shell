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
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

__all__ = ["Policy", "PolicyDecision", "Tier", "classify"]


class Tier(IntEnum):
    READ_ONLY = 0
    REVERSIBLE = 1
    STATEFUL = 2
    IRREVERSIBLE = 3


# Tools that never mutate local/remote state.
_READ_ONLY_TOOLS = frozenset(
    {"server_info", "ssh_hosts", "ssh_check", "session_list", "session_recv"}
)

# Substrings that strongly imply an irreversible / high-blast action.
_TIER3 = re.compile(
    r"(?ix)\b("
    r"rm\s+-[rf]|rm\s+-[a-z]*f|shred|mkfs|fdisk|sgdisk|wipefs|"
    r"dd\s+[^|]*of=/dev/|>\s*/dev/[sh]d|"
    r"shutdown|reboot|halt|poweroff|init\s+0|init\s+6|"
    r"drop\s+database|drop\s+table|truncate\s+table|"
    r"git\s+push\s+.*--force|git\s+reset\s+--hard|"
    r"userdel|deluser|gpasswd|passwd\s+|"
    r"iptables\s+-F|nft\s+flush|ip\s+link\s+.*down|"
    r":\s*\(\s*\)\s*\{|/dev/sd[a-z]\b"
    r")"
)

# Substrings that imply a stateful, visible change.
_TIER2 = re.compile(
    r"(?ix)\b("
    r"systemctl\s+(stop|restart|disable|mask|kill)|service\s+\S+\s+(stop|restart)|"
    r"apt(-get)?\s+(install|remove|purge|upgrade|dist-upgrade)|"
    r"yum\s+(install|remove)|dnf\s+(install|remove)|pip\s+install|npm\s+(install|i)\b|"
    r"docker\s+(run|rm|stop|kill|compose|build)|kubectl\s+(apply|delete|scale|rollout)|"
    r"chown|chmod\s+-R|chmod\s+[0-7]{3,4}\s+/|"
    r"crontab|ln\s+-s|mv\s+/|cp\s+-[a-z]*\s+/|sed\s+-i|tee\s+/etc/|"
    r"git\s+(push|commit|merge|rebase)|"
    r"ufw\s+(allow|deny|enable|disable)|"
    r"ssh-copy-id|>\s*/etc/|>>\s*/etc/"
    r")"
)

# Privilege escalation wrappers should not be treated as low-risk commands.
_PRIV_ESC = re.compile(r"(?ix)\b(sudo|doas|pkexec)\b")

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
    if _TIER3.search(text):
        return Tier.IRREVERSIBLE
    if _PRIV_ESC.search(text):
        return Tier.STATEFUL
    if _TIER2.search(text):
        return Tier.STATEFUL
    if tool in _MUTATING_TOOLS:
        return Tier.STATEFUL
    if tool in {"shell_exec", "shell_script", "ssh_exec", "shell_spawn", "ssh_spawn"}:
        # An interactive shell or arbitrary command with no obvious mutating
        # token: treat as reversible-by-default but never read-only.
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
