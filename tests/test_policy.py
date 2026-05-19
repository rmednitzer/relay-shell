from __future__ import annotations

from mcpx.policy import Policy, Tier, classify


def test_classify_read_only() -> None:
    assert classify("server_info") is Tier.READ_ONLY
    assert classify("ssh_hosts") is Tier.READ_ONLY


def test_classify_tiers() -> None:
    assert classify("shell_exec", "rm -rf /var/tmp/x") is Tier.IRREVERSIBLE
    assert classify("shell_exec", "systemctl restart nginx") is Tier.STATEFUL
    assert classify("shell_exec", "ls -la") is Tier.REVERSIBLE
    assert classify("ssh_upload", "upload a b") is Tier.STATEFUL


def test_open_mode_allows_but_classifies() -> None:
    p = Policy("open")
    d = p.check("shell_exec", "rm -rf /data")
    assert d.allowed is True
    assert d.tier is Tier.IRREVERSIBLE


def test_deny_list_wins_even_in_open() -> None:
    p = Policy("open", deny=r"forkbomb|:\(\)\s*\{")
    d = p.check("shell_exec", "forkbomb now")
    assert d.allowed is False


def test_readonly_mode() -> None:
    p = Policy("readonly")
    assert p.check("server_info").allowed is True
    assert p.check("shell_exec", "ls").allowed is False


def test_guarded_mode_requires_allow() -> None:
    p = Policy("guarded", allow=r"systemctl restart nginx")
    assert p.check("shell_exec", "systemctl restart nginx").allowed is True
    assert p.check("shell_exec", "systemctl restart postgres").allowed is False
    assert p.check("shell_exec", "ls -la").allowed is True  # Tier 1 ok
