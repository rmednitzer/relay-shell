from __future__ import annotations

from relay_shell.policy import Policy, Tier, classify


def test_classify_read_only() -> None:
    assert classify("server_info") is Tier.READ_ONLY
    assert classify("ssh_hosts") is Tier.READ_ONLY
    assert classify("ssh_forward_list") is Tier.READ_ONLY


def test_classify_tiers() -> None:
    assert classify("shell_exec", "rm -rf /var/tmp/x") is Tier.IRREVERSIBLE
    assert classify("shell_exec", "systemctl restart nginx") is Tier.STATEFUL
    assert classify("shell_exec", "sudo ls -la /root") is Tier.STATEFUL
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


def test_classify_session_send_payload() -> None:
    """Keystrokes written to a live PTY are classified by *content*, not waved
    through at the Tier-1 keystroke default.

    ``session_send`` reaches the interactive-input default (Tier 1) only when
    the payload carries no higher-tier token. A destructive payload — the same
    ``rm -rf`` / privilege token the one-shot executors escalate on — escalates
    here too, because the runner feeds the written bytes
    (``_policy_text_session_send``) through the same classifier. Without this
    the interactive path would be a blind Tier-1 hole: spawn a shell (Tier 1),
    then type anything.
    """
    assert classify("session_send", "rm -rf /") is Tier.IRREVERSIBLE
    assert classify("session_send", "sudo ls -la /root") is Tier.STATEFUL  # priv-esc
    assert classify("session_send", "systemctl restart nginx") is Tier.STATEFUL
    # Benign input falls to the keystroke default.
    assert classify("session_send", "ls -la") is Tier.REVERSIBLE
    assert classify("session_send", "") is Tier.REVERSIBLE


def test_guarded_refuses_tier3_session_send_payload() -> None:
    """Guarded mode's Tier-2+ ceiling applies to interactive input, not just
    one-shot commands: a destructive ``session_send`` payload is refused while
    benign keystrokes (Tier 1) still pass.

    NOTE: classification is per-call, so a payload fragmented across several
    ``session_send`` calls (``"rm -rf "`` then ``"/"``) evades this exactly like
    shell obfuscation evades the deny list — the ADR 0003 "heuristic, advisory,
    defence-in-depth" caveat applies. Enforce hard prohibitions with the deny
    list on the spawn tools (``^shell_spawn`` / ``^ssh_spawn``), ``readonly``
    mode, or OS controls.
    """
    p = Policy("guarded")
    assert p.check("session_send", "rm -rf /").allowed is False
    assert p.check("session_send", "ls -la").allowed is True  # Tier 1 keystrokes pass


def test_policy_checks_shell_exec_stdin_payload() -> None:
    p = Policy("open", deny=r"rm\s+-rf")
    d = p.check("shell_exec", "bash\nrm -rf /tmp/victim")
    assert d.allowed is False
    assert d.tier is Tier.IRREVERSIBLE


def test_policy_checks_shell_exec_env_payload() -> None:
    p = Policy("open", deny=r"rm\s+-rf")
    d = p.check("shell_exec", 'bash -c "$PAYLOAD"\n{"PAYLOAD":"rm -rf /tmp/victim"}')
    assert d.allowed is False
    assert d.tier is Tier.IRREVERSIBLE
