"""Tests for the `ssh_keyscan` tool (B-001).

These exercise the validation surface end to end through the FastMCP
instance. `ssh-keyscan` needs the openssh-client binary, so the happy-path
tests monkeypatch `relay_shell.server.run_command`. Validation failures run
against the real wrapper; they short-circuit before any subprocess is spawned.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from helpers import audit_lines as _audit_lines
from helpers import text as _text
from relay_shell.config import Settings
from relay_shell.policy import Tier, classify
from relay_shell.server import build_server


def test_ssh_keyscan_classified_tier_one_not_zero() -> None:
    # Tier 1, not Tier 0: it opens caller-chosen outbound TCP connections,
    # which is outside the observation-only contract of `readonly` mode even
    # though it mutates no local state. Tier 1 is permitted in `open` and
    # `guarded` and rejected in `readonly`.
    assert classify("ssh_keyscan") is Tier.REVERSIBLE


async def test_ssh_keyscan_rejects_empty_hosts(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (await mcp.call_tool("ssh_keyscan", {"hosts": ""})).content
    assert "[no hosts" in _text(content)


async def test_ssh_keyscan_rejects_shell_metachars(settings: Settings) -> None:
    # Each input is one token (no whitespace) with a character outside the
    # validator's allowed class. Newline/whitespace cases are deliberately
    # absent: split() treats them as separators, so "host\nls" becomes two
    # valid hostnames and two separate ssh-keyscan arguments (not a
    # shell-injection path).
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
        content = (await mcp.call_tool("ssh_keyscan", {"hosts": bad})).content
        text = _text(content)
        assert "rejected host" in text, f"failed to reject {bad!r}: {text!r}"


async def test_ssh_keyscan_rejects_out_of_range_port(settings: Settings) -> None:
    mcp = build_server(settings)
    for bad_port in (0, -1, 65536, 100000):
        content = (
            await mcp.call_tool("ssh_keyscan", {"hosts": "valid.example.org", "port": bad_port})
        ).content
        assert "out of range" in _text(content)


async def test_ssh_keyscan_rejects_unknown_key_type(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_keyscan",
            {"hosts": "valid.example.org", "key_types": "rsa,bogus"},
        )
    ).content
    text = _text(content)
    assert "rejected key type" in text
    assert "'bogus'" in text


async def test_ssh_keyscan_rejects_empty_key_types(settings: Settings) -> None:
    mcp = build_server(settings)
    content = (
        await mcp.call_tool(
            "ssh_keyscan",
            {"hosts": "valid.example.org", "key_types": ",,"},
        )
    ).content
    assert "empty key_types" in _text(content)


async def test_ssh_keyscan_invokes_ssh_keyscan_with_validated_argv(
    settings: Settings,
) -> None:
    # Patch run_command at the import site (server.py imports it from
    # shelltools) to capture the command string the wrapper would run.
    captured: dict[str, object] = {}

    async def fake_run_command(cmd: str, **kwargs: object) -> tuple[str, int | None]:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        # known_hosts-format line, as real ssh-keyscan prints.
        return ("host.example ssh-rsa AAAAB3NzaC1yc2E...REDACTED-FOR-TEST...\n", 0)

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        content = (
            await mcp.call_tool(
                "ssh_keyscan",
                {
                    "hosts": "host.example, other.example",
                    "port": 2222,
                    "key_types": "rsa,ed25519",
                    "timeout": 5,
                },
            )
        ).content

    out = _text(content)
    assert "host.example ssh-rsa" in out
    cmd = str(captured["cmd"])
    assert cmd.startswith("ssh-keyscan ")
    # The inner timeout is the clamped value.
    assert " -T 5 " in cmd
    assert "rsa,ed25519" in cmd
    assert " -p 2222 " in cmd
    # shlex.quote may or may not quote these, depending on characters.
    assert "host.example" in cmd
    assert "other.example" in cmd


async def test_ssh_keyscan_passes_output_cap_to_run_command(settings: Settings) -> None:
    # PERF-4 regression: ssh_keyscan's run_command call omitted output_cap
    # (unlike shell_exec/shell_script), so a misbehaving host could stream
    # unbounded output into relay memory before the per-call timeout fired.
    captured: dict[str, object] = {}

    async def fake_run_command(_cmd: str, **kwargs: object) -> tuple[str, int | None]:
        captured.update(kwargs)
        return ("", 0)

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        await mcp.call_tool("ssh_keyscan", {"hosts": "host.example"})

    assert captured.get("output_cap") == settings.max_output_hard


async def test_ssh_keyscan_rejects_oversize_host_list(settings: Settings) -> None:
    # The wrapper caps the host list at 32 to bound the outbound TCP burst;
    # a larger list short-circuits before any subprocess spawns, so the tool
    # cannot serve as a network sweep.
    mcp = build_server(settings)
    too_many = ",".join(f"host{i}.example" for i in range(33))
    content = (await mcp.call_tool("ssh_keyscan", {"hosts": too_many})).content
    text = _text(content)
    assert "exceeds the per-call cap" in text
    assert "33 hosts" in text


async def test_ssh_keyscan_passes_double_dash_separator(settings: Settings) -> None:
    # Defence in depth: the host regex permits a leading `-`. ssh-keyscan
    # does not honour option-style flags an attacker might try today, but
    # the literal `--` before the host list makes a future getopt-flavoured
    # attempt fail loudly.
    captured: dict[str, object] = {}

    async def fake_run_command(cmd: str, **_kwargs: object) -> tuple[str, int | None]:
        captured["cmd"] = cmd
        return ("", 0)

    with patch("relay_shell.server.run_command", fake_run_command):
        mcp = build_server(settings)
        await mcp.call_tool("ssh_keyscan", {"hosts": "host.example"})

    cmd = str(captured["cmd"])
    assert " -- " in cmd
    # The host comes after the separator.
    assert cmd.index(" -- ") < cmd.index("host.example")


async def test_ssh_keyscan_deny_list_gates_scan_targets(tmp_path: Path) -> None:
    # SEC-1: ssh_keyscan feeds its caller-chosen hosts to the policy layer,
    # so RELAY_SHELL_POLICY_DENY can refuse a scan target (the SSRF-shaped
    # surface). Regression: policy_text was empty, so the deny never fired on
    # the host. A denied call must short-circuit before any subprocess and be
    # audited as denied=True.
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
        content = (await mcp.call_tool("ssh_keyscan", {"hosts": "169.254.169.254"})).content

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
        content = (await mcp.call_tool("ssh_keyscan", {"hosts": "host.example"})).content

    out = _text(content)
    assert "DENIED" not in out and "ssh-ed25519" in out
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["denied"] is False
    assert last["tier"] == int(Tier.REVERSIBLE)


def test_ssh_keyscan_hosts_reach_classifier_documents_tradeoff() -> None:
    # SEC-1 tradeoff (documented in _policy_text_ssh_keyscan + BACKLOG SEC-1):
    # feeding the hosts to the deny list also feeds them to the tier
    # classifier, so a host whose name embeds a destructive word at a token
    # start over-classifies above Tier 1. It only bites `guarded` mode (open
    # is advisory, readonly already refuses Tier 1); POLICY_ALLOW is the
    # escape hatch.
    assert classify("ssh_keyscan", "web01.example.com") is Tier.REVERSIBLE
    # `reboot` is only a Tier 3 token in command position (patterns v12), so a
    # dotted hostname that merely starts with it does not trip the classifier,
    assert classify("ssh_keyscan", "reboot.example.com") is Tier.REVERSIBLE
    # but a host that is literally the bare word does (the remaining tradeoff).
    assert classify("ssh_keyscan", "reboot") is Tier.IRREVERSIBLE


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

    # Decimal, hex, octal and dotted-short forms collapse to the dotted quad.
    assert "127.0.0.1" in _canonical_ips("2130706433")
    assert "127.0.0.1" in _canonical_ips("0x7f000001")
    assert "127.0.0.1" in _canonical_ips("0177.0.0.1")
    assert "127.0.0.1" in _canonical_ips("127.1")
    # IPv4-mapped IPv6 yields the embedded v4 address.
    assert "127.0.0.1" in _canonical_ips("::ffff:127.0.0.1")
    # A standard literal maps to itself.
    assert _canonical_ips("169.254.169.254") == ["169.254.169.254"]


def test_canonical_ips_ignores_hostnames_and_ports() -> None:
    from relay_shell.server import _canonical_ips

    # Hostnames are never resolved (no DNS in the policy path).
    assert _canonical_ips("web01.example.com") == []
    assert _canonical_ips("localhost") == []
    # A bare small integer (port, count) is not turned into 0.0.0.N.
    assert _canonical_ips("22") == []


def test_augment_probe_appends_only_differing_forms() -> None:
    from relay_shell.server import _augment_probe_with_ips

    assert _augment_probe_with_ips("2130706433") == "2130706433 127.0.0.1"
    # Plain literals and hostnames are left untouched (no duplicates).
    assert _augment_probe_with_ips("127.0.0.1") == "127.0.0.1"
    assert _augment_probe_with_ips("web01.example.com") == "web01.example.com"


async def test_ssh_keyscan_deny_not_dodged_by_ip_encoding(tmp_path: Path) -> None:
    # SSRF-1: an operator deny on the dotted-quad metadata IP must still fire
    # when the caller spells it as a packed decimal (or another encoding); the
    # canonical form is appended to the deny probe.
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
        content = (await mcp.call_tool("ssh_keyscan", {"hosts": obfuscated})).content

    out = _text(content)
    assert "DENIED" in out, f"obfuscated-IP scan target must be denied; got {out!r}"
    last = _audit_lines(Path(settings.audit_path))[-1]
    assert last["denied"] is True
    # The raw caller token, not the canonical form, is audited (redaction runs on it).
    assert last["args"]["hosts"] == obfuscated
