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

import json
import os
from collections.abc import Mapping, Sequence
from typing import Any

from .config import Settings
from .policy import BASIS_PRIVILEGE, PolicyDecision, Tier

__all__ = [
    "NOTICE_MIN_TIER",
    "attach_notices",
    "call_notices",
    "config_warnings",
    "format_notices",
    "unverified_host_notice",
]

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


def unverified_host_notice(hosts: Sequence[str]) -> list[str]:
    """Notice for the hosts a call connects to with host-key verification off.

    For the tools that resolve their targets inside the work (``ssh_check``,
    ``ssh_fanout``), where the mode is the server default or an inventory entry's own.
    """
    if not hosts:
        return []
    shown = ", ".join(hosts[:5]) + (f" and {len(hosts) - 5} more" if len(hosts) > 5 else "")
    return [
        f"ssh: host-key verification is off for {shown} (known_hosts=ignore); the peer is not "
        "authenticated and the connection can be intercepted"
    ]


def format_notices(notes: Sequence[str]) -> str:
    """Render notices as trailing ``[NOTICE ...]`` lines (empty string for none)."""
    return "".join(f"\n[NOTICE {note}]" for note in notes)


def attach_notices(text: str, notes: Sequence[str], *, as_json: bool = False) -> str:
    """Add ``notes`` to a tool result.

    Text results get trailing ``[NOTICE ...]`` lines. A tool whose result is a JSON object
    (``ssh_fanout``) passes ``as_json=True`` and gets a ``"notices"`` array inside the object
    instead, so the result still parses; if the text is not a JSON object (an error string, a
    truncated body) the trailing lines are used.
    """
    if not notes:
        return text
    if as_json:
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            doc["notices"] = list(notes)
            return json.dumps(doc, default=str)
    return text + format_notices(notes)


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
        listed = "a deny list is set" if settings.policy_deny else "no RELAY_SHELL_POLICY_DENY"
        if settings.confirm_tier3:
            effect = (
                "irreversible (Tier 3) commands need the two-step confirmation, every other "
                "command runs on the first request"
            )
        else:
            effect = (
                "irreversible commands run on the first request (RELAY_SHELL_CONFIRM_TIER3 off)"
            )
        warnings.append(
            f"policy mode is open ({listed}): {effect}; 'guarded' or 'readonly' narrows this"
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
