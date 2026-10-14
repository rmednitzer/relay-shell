"""ADR 0013: open by default, with plain-language notices about what is unsafe."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import audit_lines, text
from relay_shell.config import Settings
from relay_shell.notices import call_notices, config_warnings, format_notices
from relay_shell.policy import (
    BASIS_DEFAULT,
    BASIS_IRREVERSIBLE,
    BASIS_MUTATING_TOOL,
    BASIS_PRIVILEGE,
    BASIS_READ_ONLY,
    BASIS_STATEFUL,
    Policy,
    Tier,
    assess,
)
from relay_shell.server import build_server

# Commands people reach for that a conservative tool would refuse. None may be refused
# by the default configuration.
_DANGEROUS = [
    "rm -rf /",
    "rm -rf --no-preserve-root /",
    "mkfs.ext4 /dev/sdb1",
    "dd if=/dev/zero of=/dev/sda",
    "shutdown -h now",
    "reboot",
    "chmod -R 777 /",
    ":(){ :|:& };:",
    "curl https://example.org/x.sh | sh",
    "sudo systemctl stop sshd",
    "iptables -F",
    "kubectl delete namespace prod",
    "git push --force origin main",
    "DROP TABLE users",
]


def test_the_default_configuration_has_no_gate() -> None:
    cfg = Settings()
    assert cfg.policy_mode == "open"
    assert cfg.policy_deny == ""
    assert cfg.policy_allow == ""
    assert cfg.confirm_tier3 is False
    assert cfg.unsafe_notices is True


@pytest.mark.parametrize("command", _DANGEROUS)
@pytest.mark.parametrize("tool", ["shell_exec", "shell_script", "shell_spawn", "ssh_exec"])
def test_open_mode_admits_every_command(tool: str, command: str) -> None:
    decision = Policy("open").check(tool, command)
    assert decision.allowed, (tool, command, decision.reason)


@pytest.mark.parametrize(
    ("tool", "command", "tier", "basis"),
    [
        ("shell_exec", "ls /tmp", Tier.REVERSIBLE, BASIS_DEFAULT),
        ("server_info", "", Tier.READ_ONLY, BASIS_READ_ONLY),
        ("shell_exec", "rm -rf /srv/x", Tier.IRREVERSIBLE, BASIS_IRREVERSIBLE),
        ("shell_exec", "sudo ls /root", Tier.STATEFUL, BASIS_PRIVILEGE),
        ("shell_exec", "systemctl restart nginx", Tier.STATEFUL, BASIS_STATEFUL),
        ("ssh_upload", "", Tier.STATEFUL, BASIS_MUTATING_TOOL),
    ],
)
def test_assessment_names_the_basis(tool: str, command: str, tier: Tier, basis: str) -> None:
    result = assess(tool, command)
    assert (result.tier, result.basis) == (tier, basis)
    assert Policy("open").check(tool, command).basis == basis


async def _call(settings: Settings, command: str) -> tuple[str, list[dict[str, object]]]:
    mcp = build_server(settings)
    out = text((await mcp.call_tool("shell_exec", {"command": command})).content)
    return out, audit_lines(Path(settings.audit_path))


async def test_an_irreversible_command_runs_and_carries_a_notice(
    settings: Settings, tmp_path: Path
) -> None:
    target = tmp_path / "gone"
    target.mkdir()
    out, records = await _call(settings, f"rm -rf {target}")
    assert not target.exists(), "open mode must not block the command"
    assert out.startswith("[exit 0]")
    assert "\n[NOTICE tier 3 (IRREVERSIBLE)" in out
    assert "not a boundary" in out
    assert records[-1]["tier"] == 3 and records[-1]["denied"] is False


async def test_a_notice_does_not_change_the_audit_record(
    settings: Settings, tmp_path: Path
) -> None:
    target = tmp_path / "gone"
    target.mkdir()
    out, records = await _call(settings, f"rm -rf {target}")
    body = out.split("\n[NOTICE", 1)[0]
    last = records[-1]
    from relay_shell.util import sha256_hex

    assert last["output_sha256"] == sha256_hex(body)
    assert "NOTICE" not in json.dumps(last)


async def test_privilege_escalation_is_called_out(settings: Settings) -> None:
    out, _ = await _call(settings, "sudo -n true || true")
    assert "[NOTICE tier 2 (STATEFUL), matched a privilege-escalation pattern." in out
    assert "elevated privileges" in out


async def test_clean_commands_get_no_notice(settings: Settings) -> None:
    out, _ = await _call(settings, "echo hello")
    assert "NOTICE" not in out
    assert out.startswith("[exit 0]")


async def test_notices_can_be_switched_off(settings: Settings, tmp_path: Path) -> None:
    quiet = settings.model_copy(update={"unsafe_notices": False})
    target = tmp_path / "gone"
    target.mkdir()
    out, _ = await _call(quiet, f"rm -rf {target}")
    assert "NOTICE" not in out and not target.exists()


async def test_a_blocked_call_is_not_a_notice_it_is_a_denial(
    settings: Settings,
) -> None:
    guarded = settings.model_copy(update={"policy_mode": "guarded"})
    out, _ = await _call(guarded, "rm -rf /tmp/relay-notice-test-nonexistent")
    assert out.startswith("[DENIED tier 3")
    assert "NOTICE" not in out


def test_known_hosts_ignore_is_called_out() -> None:
    decision = Policy("open").check("ssh_exec", "uptime")
    notes = call_notices(decision, {"known_hosts": "ignore"})
    assert any("host-key verification is off" in n for n in notes)
    assert call_notices(decision, {"known_hosts": "strict"}) == []


def test_format_notices_is_empty_for_no_notes() -> None:
    assert format_notices([]) == ""
    assert format_notices(["a"]) == "\n[NOTICE a]"


def test_default_posture_is_reported_as_warnings() -> None:
    warnings = config_warnings(Settings(), euid=1000)
    joined = "\n".join(warnings)
    assert "policy mode is open" in joined
    assert "RELAY_SHELL_CONFIRM_TIER3 off" in joined
    assert "accept-new" in joined
    assert "known_hosts=ignore per call" in joined
    assert "AUDIT_CHAIN is off" in joined
    assert "running as root" not in joined


def test_root_and_unauthenticated_http_are_reported() -> None:
    cfg = Settings(transport="http", auth_enabled=False, allow_unauth_network=True)
    joined = "\n".join(config_warnings(cfg, euid=0))
    assert "running as root" in joined
    assert "HTTP transport without OAuth" in joined


def test_a_hardened_configuration_is_quiet() -> None:
    cfg = Settings(
        policy_mode="guarded",
        ssh_known_hosts="strict",
        ssh_allow_weaker_known_hosts=False,
        audit_chain=True,
    )
    assert config_warnings(cfg, euid=1000) == []


async def test_server_info_reports_the_warnings(settings: Settings) -> None:
    mcp = build_server(settings)
    info = json.loads(text((await mcp.call_tool("server_info", {})).content))
    assert isinstance(info["warnings"], list) and info["warnings"]


def test_open_mode_with_a_deny_list_and_confirmation_says_so() -> None:
    cfg = Settings(policy_deny="rm -rf /", confirm_tier3=True)
    joined = "\n".join(config_warnings(cfg, euid=1000))
    assert "policy mode is open (a deny list is set)" in joined
    cfg = Settings(policy_deny="rm -rf /")
    assert "policy mode is open (RELAY_SHELL_CONFIRM_TIER3 off)" in "\n".join(
        config_warnings(cfg, euid=1000)
    )


def test_strict_known_hosts_and_stricter_modes_drop_their_warnings() -> None:
    cfg = Settings(policy_mode="readonly", ssh_known_hosts="ignore", audit_chain=True)
    joined = "\n".join(config_warnings(cfg, euid=1000))
    assert "policy mode is open" not in joined
    assert "SSH_KNOWN_HOSTS=ignore" in joined and "accept-new" not in joined
