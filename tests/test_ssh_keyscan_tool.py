"""Tests for the `ssh_keyscan` tool (B-001).

These exercise the validation surface end-to-end through the FastMCP
instance. The actual `ssh-keyscan` invocation requires the openssh-client
binary on the host, so the tests substitute the executor by monkeypatching
`relay_shell.server.run_command` for the "happy path" case. Validation
failures are exercised against the real wrapper - they short-circuit
before any subprocess is spawned.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from relay_shell.config import Settings
from relay_shell.policy import Tier, classify
from relay_shell.server import build_server


def _audit_lines(path: Path) -> list[dict[str, object]]:
    text = path.read_text(encoding="utf-8")
    return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


def _text(content: object) -> str:
    return "".join(b.text for b in content if getattr(b, "type", "") == "text")


def test_ssh_keyscan_classified_tier_one_not_zero() -> None:
    # ssh_keyscan is Tier 1 (REVERSIBLE), not Tier 0. It opens
    # caller-chosen outbound TCP connections, which puts it outside
    # the "observation-only" contract of `readonly` mode even though
    # it does not mutate local state. Tier 1 keeps it permitted in
    # `open` and `guarded` modes but rejected in `readonly`.
    assert classify("ssh_keyscan") is Tier.REVERSIBLE


async def test_ssh_keyscan_rejects_empty_hosts(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("ssh_keyscan", {"hosts": ""})
    assert "[no hosts" in _text(content)


async def test_ssh_keyscan_rejects_shell_metachars(settings: Settings) -> None:
    # Each input is a single token (no whitespace) that contains a
    # character outside the validator's allowed class. Newline /
    # whitespace cases are deliberately NOT in this list because
    # split() treats them as separators, not metachars: "host\nls"
    # tokenizes to ["host", "ls"], both of which are valid hostnames
    # in their own right and would land as two separate ssh-keyscan
    # arguments (not a shell-injection path).
    mcp = build_server(settings)
    for bad in (
        "host;rm",  # semicolon
        "host`id`",  # backtick
        "host$(id)",  # subshell
        "host&",  # background
        "host|cat",  # pipe
        "host*glob",  # glob
        "host>out",  # redirect
        "host'q'",  # single quote
        'host"q"',  # double quote
        "host\\esc",  # backslash
    ):
        content, _ = await mcp.call_tool("ssh_keyscan", {"hosts": bad})
        text = _text(content)
        assert "rejected host" in text, f"failed to reject {bad!r}: {text!r}"


async def test_ssh_keyscan_rejects_out_of_range_port(settings: Settings) -> None:
    mcp = build_server(settings)
    for bad_port in (0, -1, 65536, 100000):
        content, _ = await mcp.call_tool(
            "ssh_keyscan", {"hosts": "valid.example.org", "port": bad_port}
        )
        assert "out of range" in _text(content)


async def test_ssh_keyscan_rejects_unknown_key_type(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_keyscan",
        {"hosts": "valid.example.org", "key_types": "rsa,bogus"},
    )
    text = _text(content)
    assert "rejected key type" in text
    assert "'bogus'" in text


async def test_ssh_keyscan_rejects_empty_key_types(settings: Settings) -> None:
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "ssh_keyscan",
        {"hosts": "valid.example.org", "key_types": ",,"},
    )
    assert "empty key_types" in _text(content)


async def test_ssh_keyscan_invokes_ssh_keyscan_with_validated_argv(
    settings: Settings,
) -> None:
    # Patch run_command at the import site (server.py imports it from
    # shelltools). Capture the command string the wrapper would have
    # passed to a real shell.
    captured: dict[str, object] = {}

    async def fake_run_command(cmd: str, **kwargs: object) -> tuple[str, int | None]:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        # known_hosts-format line, like real ssh-keyscan output.
        return ("host.example ssh-rsa AAAAB3NzaC1yc2E...REDACTED-FOR-TEST...\n", 0)

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        content, _ = await mcp.call_tool(
            "ssh_keyscan",
            {
                "hosts": "host.example, other.example",
                "port": 2222,
                "key_types": "rsa,ed25519",
                "timeout": 5,
            },
        )

    out = _text(content)
    assert "host.example ssh-rsa" in out
    # The wrapper built the command from validated tokens, in argv order.
    cmd = str(captured["cmd"])
    assert cmd.startswith("ssh-keyscan ")
    # Inner timeout is the clamped value.
    assert " -T 5 " in cmd
    # Key types passed as one comma list.
    assert "rsa,ed25519" in cmd
    # Port forwarded as integer.
    assert " -p 2222 " in cmd
    # Both hosts present (shlex.quote may or may not quote depending on chars).
    assert "host.example" in cmd
    assert "other.example" in cmd


async def test_ssh_keyscan_rejects_oversize_host_list(settings: Settings) -> None:
    # The wrapper caps `len(host_list)` at 32 to bound the outbound
    # TCP burst. A larger list short-circuits before any subprocess
    # spawns, so even a noisy caller cannot turn this into a network
    # sweep tool.
    mcp = build_server(settings)
    too_many = ",".join(f"host{i}.example" for i in range(33))
    content, _ = await mcp.call_tool("ssh_keyscan", {"hosts": too_many})
    text = _text(content)
    assert "exceeds the per-call cap" in text
    assert "33 hosts" in text


async def test_ssh_keyscan_passes_double_dash_separator(settings: Settings) -> None:
    # Belt-and-braces: the host regex permits leading `-`. Even though
    # ssh-keyscan does not honour the option-style flags an attacker
    # might try, the literal `--` between options and the host list
    # makes any future getopt-flavoured attempt fail loudly.
    captured: dict[str, object] = {}

    async def fake_run_command(cmd: str, **_kwargs: object) -> tuple[str, int | None]:
        captured["cmd"] = cmd
        return ("", 0)

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        await mcp.call_tool("ssh_keyscan", {"hosts": "host.example"})

    cmd = str(captured["cmd"])
    # The literal "--" appears between the last option and the first host.
    assert " -- " in cmd
    # And the host comes AFTER it.
    assert cmd.index(" -- ") < cmd.index("host.example")


async def test_ssh_keyscan_deny_list_gates_scan_targets(tmp_path: Path) -> None:
    # SEC-1: ssh_keyscan now feeds its caller-chosen hosts to the policy
    # layer, so RELAY_SHELL_POLICY_DENY can refuse a scan target (the
    # SSRF-shaped surface). Pre-fix policy_text was empty and the deny
    # never fired on the host. A denied call must short-circuit before any
    # subprocess and be audited as denied=True.
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"169\.254\.169\.254",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )

    async def fake_run_command(_cmd: str, **_kwargs: object) -> tuple[str, int | None]:
        raise AssertionError("a denied ssh_keyscan must not reach the executor")

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        content, _ = await mcp.call_tool("ssh_keyscan", {"hosts": "169.254.169.254"})

    out = _text(content)
    assert "DENIED" in out, f"deny pattern on the scan host must fire; got {out!r}"
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["tool"] == "ssh_keyscan"
    assert last["denied"] is True
    # The host is still recorded in the audit args (redaction runs on it).
    assert last["args"]["hosts"] == "169.254.169.254"


async def test_ssh_keyscan_allowed_when_host_not_denied(tmp_path: Path) -> None:
    # A non-matching host is admitted at the default Tier 1 and runs.
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"169\.254\.169\.254",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )

    async def fake_run_command(_cmd: str, **_kwargs: object) -> tuple[str, int | None]:
        return ("host.example ssh-ed25519 AAAA...\n", 0)

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        content, _ = await mcp.call_tool("ssh_keyscan", {"hosts": "host.example"})

    out = _text(content)
    assert "DENIED" not in out and "ssh-ed25519" in out
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["denied"] is False
    assert last["tier"] == int(Tier.REVERSIBLE)


def test_ssh_keyscan_hosts_reach_classifier_documents_tradeoff() -> None:
    # SEC-1 tradeoff (documented in _policy_text_ssh_keyscan + BACKLOG SEC-1):
    # feeding the hosts to the deny list also feeds them to the tier
    # classifier, so a host whose name embeds a destructive word at a token
    # start over-classifies above Tier 1. This pins the known behavior so a future
    # reader is not surprised: it only bites `guarded` mode (open is advisory,
    # readonly already refuses Tier 1), with POLICY_ALLOW as the escape hatch.
    assert classify("ssh_keyscan", "web01.example.com") is Tier.REVERSIBLE
    # "reboot" is a Tier 3 token; a host literally named so trips it.
    assert classify("ssh_keyscan", "reboot.example.com") is Tier.IRREVERSIBLE


async def test_ssh_keyscan_audits_its_args(settings: Settings) -> None:
    async def fake_run_command(_cmd: str, **_kwargs: object) -> tuple[str, int | None]:
        return ("", 0)

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        await mcp.call_tool(
            "ssh_keyscan",
            {"hosts": "host.example", "port": 22, "key_types": "rsa"},
        )

    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["tool"] == "ssh_keyscan"
    assert last["args"]["hosts"] == "host.example"
    assert last["args"]["port"] == 22
    assert last["args"]["key_types"] == "rsa"


# --- SSRF-1: IP-encoding normalization into the deny probe ----------------


def test_canonical_ips_normalizes_obfuscated_ipv4() -> None:
    from relay_shell.server import _canonical_ips

    # Decimal / hex / octal / dotted-short all collapse to the dotted quad.
    assert "127.0.0.1" in _canonical_ips("2130706433")
    assert "127.0.0.1" in _canonical_ips("0x7f000001")
    assert "127.0.0.1" in _canonical_ips("0177.0.0.1")
    assert "127.0.0.1" in _canonical_ips("127.1")
    # IPv4-mapped IPv6 exposes the embedded v4 address.
    assert "127.0.0.1" in _canonical_ips("::ffff:127.0.0.1")
    # A standard literal canonicalizes to itself.
    assert _canonical_ips("169.254.169.254") == ["169.254.169.254"]


def test_canonical_ips_ignores_hostnames_and_ports() -> None:
    from relay_shell.server import _canonical_ips

    # Hostnames are never resolved (no DNS in the policy path).
    assert _canonical_ips("web01.example.com") == []
    assert _canonical_ips("localhost") == []
    # A bare small integer (port/count) is not turned into 0.0.0.N.
    assert _canonical_ips("22") == []


def test_augment_probe_appends_only_differing_forms() -> None:
    from relay_shell.server import _augment_probe_with_ips

    assert _augment_probe_with_ips("2130706433") == "2130706433 127.0.0.1"
    # Plain literals and hostnames are left untouched (no noisy duplicates).
    assert _augment_probe_with_ips("127.0.0.1") == "127.0.0.1"
    assert _augment_probe_with_ips("web01.example.com") == "web01.example.com"


async def test_ssh_keyscan_deny_not_dodged_by_ip_encoding(tmp_path: Path) -> None:
    # SSRF-1: an operator deny on the dotted-quad metadata IP must still fire
    # when the caller spells it as a packed decimal (or any other encoding),
    # because the canonical form is appended to the deny probe.
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        policy_deny=r"169\.254\.169\.254",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
    )

    async def fake_run_command(_cmd: str, **_kwargs: object) -> tuple[str, int | None]:
        raise AssertionError("a denied ssh_keyscan must not reach the executor")

    # 169.254.169.254 packed as a single decimal integer (0xA9FEA9FE).
    obfuscated = "2852039166"
    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        content, _ = await mcp.call_tool("ssh_keyscan", {"hosts": obfuscated})

    out = _text(content)
    assert "DENIED" in out, f"obfuscated-IP scan target must be denied; got {out!r}"
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["denied"] is True
    # The raw caller token is what is audited (redaction runs on it).
    assert last["args"]["hosts"] == obfuscated
