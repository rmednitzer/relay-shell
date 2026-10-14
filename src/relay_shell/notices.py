"""Plain-language notices about operations and settings that are unsafe.

relay-shell admits every command by default (``RELAY_SHELL_POLICY_MODE=open``, empty deny
list, no confirmation step): a refusal is something the operator configures, never a
surprise. The counterpart is that the caller is told when what it just did, or what the
server is configured to allow, carries risk. Two surfaces:

* :func:`call_notices` - one-line ``[NOTICE ...]`` text appended to the result of a call
  that ran with a risky classification or a weakened SSH setting. The audit record is
  unchanged; the notice is a message to the caller, not evidence.
* :func:`config_warnings` - the standing posture, reported by ``server_info`` and logged
  at startup.

Neither is a control. The classifier is a regex heuristic over the command text and is not
a boundary around the shell language (see ``docs/adr/0003-tiered-authority.md``); a command
without a notice is not thereby safe, and the executor has no sandbox.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from .config import Settings
from .policy import BASIS_PRIVILEGE, PolicyDecision, Tier

__all__ = ["NOTICE_MIN_TIER", "call_notices", "config_warnings", "format_notices"]

# Tier 2 and above get a notice; Tier 0/1 calls (reads, and commands with nothing
# state-changing in them) stay clean so the notice keeps its meaning.
NOTICE_MIN_TIER = Tier.STATEFUL

_TIER_ADVICE = {
    Tier.IRREVERSIBLE: (
        "It may not be undoable and ran with no confirmation step; "
        "verify the target and take a backup or snapshot first"
    ),
    Tier.STATEFUL: "It changes state that a user or dependent service may notice",
}

_PRIVILEGE_ADVICE = (
    "It runs with elevated privileges and can change anything the target account can"
)


def call_notices(
    decision: PolicyDecision,
    audit_args: Mapping[str, Any],
) -> list[str]:
    """Notices for one admitted call: its tier, and any weakened SSH setting it used."""
    notes: list[str] = []
    tier = decision.tier
    if tier >= NOTICE_MIN_TIER:
        advice = _PRIVILEGE_ADVICE if decision.basis == BASIS_PRIVILEGE else _TIER_ADVICE[tier]
        notes.append(
            f"tier {int(tier)} ({tier.name}), {decision.basis}. {advice}. "
            "Classification is a heuristic, not a boundary"
        )
    if str(audit_args.get("known_hosts", "")).lower() == "ignore":
        notes.append(
            "ssh: host-key verification is off (known_hosts=ignore); the peer is not "
            "authenticated and the connection can be intercepted"
        )
    return notes


def format_notices(notes: list[str]) -> str:
    """Render notices as trailing ``[NOTICE ...]`` lines (empty string for none)."""
    return "".join(f"\n[NOTICE {note}]" for note in notes)


def config_warnings(settings: Settings, *, euid: int | None = None) -> list[str]:
    """The standing unsafe-by-configuration facts, in plain words.

    Each entry names what is permitted and the setting that narrows it. An empty list means
    none of the checked settings is in its permissive state; it is not a security statement.
    """
    uid = os.geteuid() if euid is None else euid
    warnings: list[str] = []
    if uid == 0:
        warnings.append(
            "running as root: every command, session and SSH key use has root's reach; "
            "there is no internal sandbox"
        )
    if settings.policy_mode == "open":
        gate = []
        if not settings.policy_deny:
            gate.append("no RELAY_SHELL_POLICY_DENY")
        if not settings.confirm_tier3:
            gate.append("RELAY_SHELL_CONFIRM_TIER3 off")
        warnings.append(
            "policy mode is open ("
            + ", ".join(gate or ["a deny list is set"])
            + "): irreversible commands run on the first request; "
            "'guarded' or 'readonly' narrows this"
        )
    if settings.ssh_known_hosts == "ignore":
        warnings.append(
            "RELAY_SHELL_SSH_KNOWN_HOSTS=ignore: SSH host keys are not verified by default"
        )
    elif settings.ssh_known_hosts == "accept-new":
        warnings.append(
            "RELAY_SHELL_SSH_KNOWN_HOSTS=accept-new: an unknown host key is trusted on first "
            "contact; 'strict' with ssh_keyscan removes the exposure"
        )
    if settings.ssh_allow_weaker_known_hosts:
        warnings.append(
            "a caller may pass known_hosts=ignore per call "
            "(RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false refuses it)"
        )
    if settings.transport == "http" and not settings.auth_enabled:
        warnings.append(
            "HTTP transport without OAuth: any client that reaches the port can run commands "
            "as the service user"
        )
    if not settings.audit_chain:
        warnings.append(
            "RELAY_SHELL_AUDIT_CHAIN is off: the audit log is not tamper-evident on its own"
        )
    return warnings
