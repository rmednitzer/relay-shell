"""ADR 0015: operator approval of Tier-3 confirmations with SSH signatures.

Keys are generated per test with asyncssh (synthetic; nothing leaves tmp_path).
The guards cover the verifier (namespace, exact challenge, allowed keys, strict
file loading), the broker (only a signed approval arms, client binding and
expiry kept) and the server wiring (plan shows the challenge, the arm record
names the approver, a forged or reused signature does not execute anything).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import asyncssh
import pytest

from helpers import text as _text
from relay_shell.approval import (
    CHALLENGE_PREFIX,
    MAX_SIGNATURE_CHARS,
    NAMESPACE,
    SignatureVerifier,
    build_challenge,
    signature_namespace,
)
from relay_shell.broker import ConfirmationBroker
from relay_shell.config import Settings
from relay_shell.server import build_server

# --- fixtures ------------------------------------------------------------


def _key() -> asyncssh.SSHKey:
    return asyncssh.generate_private_key("ssh-ed25519")


def _signers_file(tmp_path: Path, *entries: tuple[str, asyncssh.SSHKey], mode: int = 0o644) -> str:
    path = tmp_path / "allowed_signers"
    lines = [
        f"{principal} {key.export_public_key('openssh').decode().strip()}"
        for principal, key in entries
    ]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(mode)
    return str(path)


def _sign(key: asyncssh.SSHKey, data: str, namespace: str = NAMESPACE) -> str:
    return asyncssh.create_sshsig(key, data.encode(), namespace=namespace).decode()


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _challenge(token: str = "tok", op: str = "ab" * 32) -> str:
    return build_challenge(
        token=token,
        tool="shell_exec",
        args={"command": "rm -rf /srv/old", "cwd": "/"},
        op_hash=op,
        expires="2026-11-23T20:41:00Z",
        server="relay",
    )


# --- challenge line ------------------------------------------------------


def test_challenge_is_one_ascii_line_naming_the_operation() -> None:
    line = _challenge()
    assert line.startswith(CHALLENGE_PREFIX)
    assert "\n" not in line and "\r" not in line
    line.encode("ascii")  # signed bytes survive copy/paste unchanged
    body = json.loads(line[len(CHALLENGE_PREFIX) :])
    assert body["tool"] == "shell_exec"
    assert "rm -rf /srv/old" in body["args"]
    assert body["op"] == "ab" * 32
    assert body["exp"] == "2026-11-23T20:41:00Z"
    assert body["server"] == "relay"
    assert len(body["id"]) == 12


def test_challenge_truncates_long_args_but_keeps_the_binding() -> None:
    line = build_challenge(
        token="t",
        tool="shell_exec",
        args={"command": "x" * 50_000},
        op_hash="cd" * 32,
        expires="e",
        server="s",
    )
    body = json.loads(line[len(CHALLENGE_PREFIX) :])
    assert body["args"].endswith("[truncated; bound by op]")
    assert body["op"] == "cd" * 32
    assert len(line) < 6000


# --- signature parsing ---------------------------------------------------


def test_signature_namespace_reads_the_header() -> None:
    key = _key()
    assert signature_namespace(_sign(key, "x")) == NAMESPACE
    assert signature_namespace(_sign(key, "x", namespace="git")) == "git"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not a signature",
        "-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----",
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----",  # magic only
        "-----BEGIN SSH SIGNATURE-----\nQUFBQUFBQUFBQUFB\n-----END SSH SIGNATURE-----",
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAf////8=\n-----END SSH SIGNATURE-----",
    ],
)
def test_signature_namespace_rejects_malformed(bad: str) -> None:
    assert signature_namespace(bad) is None


# --- verifier ------------------------------------------------------------


def test_verifier_accepts_the_operator_signature(tmp_path: Path) -> None:
    key = _key()
    v = SignatureVerifier(_signers_file(tmp_path, ("operator@example", key)))
    line = _challenge()
    assert v.verify(line, _sign(key, line)) == "operator@example"
    # The same line saved with a trailing LF or CRLF is the same approval.
    assert v.verify(line, _sign(key, line + "\n")) == "operator@example"
    assert v.verify(line, _sign(key, line + "\r\n")) == "operator@example"
    assert v.describe()[0]["principal"] == "operator@example"
    assert v.describe()[0]["fingerprint"].startswith("SHA256:")


def test_verifier_refuses_everything_else(tmp_path: Path) -> None:
    key, stranger = _key(), _key()
    v = SignatureVerifier(_signers_file(tmp_path, ("operator@example", key)))
    line = _challenge()
    other = _challenge(token="other-token")
    good = _sign(key, line)
    assert v.verify(line, _sign(key, line, namespace="git")) is None  # wrong purpose
    assert v.verify(line, _sign(key, "file", namespace=NAMESPACE)) is None  # other data
    assert v.verify(other, good) is None  # a signature for one challenge only
    assert v.verify(line, _sign(stranger, line)) is None  # key not allowed
    assert v.verify(line, "") is None
    assert v.verify(line, good.replace("A", "B", 1)) is None  # tampered
    assert v.verify(line, good + " " * MAX_SIGNATURE_CHARS) is None  # oversize
    assert v.verify(line + " ", good) is None  # not the issued line


def test_verifier_with_namespace_restricted_entry(tmp_path: Path) -> None:
    key = _key()
    path = tmp_path / "allowed_signers"
    pub = key.export_public_key("openssh").decode().strip()
    path.write_text(f'operator@example namespaces="{NAMESPACE}" {pub}\n')
    path.chmod(0o644)
    v = SignatureVerifier(str(path))
    line = _challenge()
    assert v.verify(line, _sign(key, line)) == "operator@example"


@pytest.mark.parametrize(
    ("content", "mode", "message"),
    [
        (None, 0o644, "No such file"),
        ("", 0o644, "no entries"),
        ("# only a comment\n", 0o644, "no entries"),
        ("operator@example ssh-ed25519 not-base64\n", 0o644, ":1:"),
        ("*@example {pub}\n", 0o644, "plain names"),
        ("!evil,ok {pub}\n", 0o644, "plain names"),
        ("ca@example cert-authority {pub}\n", 0o644, "cert-authority"),
        ("operator@example {pub}\n", 0o664, "writable by group or other"),
        ("operator@example {pub}\n", 0o646, "writable by group or other"),
    ],
)
def test_verifier_fails_fast_on_ambiguous_files(
    tmp_path: Path, content: str | None, mode: int, message: str
) -> None:
    path = tmp_path / "allowed_signers"
    if content is not None:
        pub = _key().export_public_key("openssh").decode().strip()
        path.write_text(content.replace("{pub}", pub))
        path.chmod(mode)
    with pytest.raises(ValueError, match=re.escape(message)):
        SignatureVerifier(str(path))


def test_verifier_requires_a_path() -> None:
    with pytest.raises(ValueError, match="CONFIRM_ALLOWED_SIGNERS"):
        SignatureVerifier("")


# --- broker --------------------------------------------------------------


def _signed_broker(tmp_path: Path, key: asyncssh.SSHKey) -> tuple[ConfirmationBroker, _Clock]:
    clock = _Clock()
    v = SignatureVerifier(_signers_file(tmp_path, ("operator@example", key)))
    return ConfirmationBroker(60, clock=clock, verifier=v.verify), clock


def _describe(token: str, op_hash: str) -> str:
    return _challenge(token=token, op=op_hash)


def test_broker_arms_only_with_a_signature(tmp_path: Path) -> None:
    key = _key()
    broker, _ = _signed_broker(tmp_path, key)
    assert broker.requires_signature
    ch = broker.plan("shell_exec", "rm -rf /x", "client-a", describe=_describe)
    assert ch.text.startswith(CHALLENGE_PREFIX)
    assert broker.arm(ch.token, "client-a") is False  # the client alone cannot arm
    assert broker.consume("shell_exec", "rm -rf /x", "client-a") is False
    assert broker.arm_signed(ch.token, "client-a", _sign(key, ch.text)) == "operator@example"
    assert broker.consume("shell_exec", "rm -rf /x", "client-a") is True
    assert broker.consume("shell_exec", "rm -rf /x", "client-a") is False  # single use


def test_broker_signature_for_one_plan_does_not_arm_another(tmp_path: Path) -> None:
    key = _key()
    broker, _ = _signed_broker(tmp_path, key)
    benign = broker.plan("shell_exec", "rm -rf /tmp/x", "c", describe=_describe)
    harmful = broker.plan("shell_exec", "rm -rf /srv", "c", describe=_describe)
    assert broker.arm_signed(harmful.token, "c", _sign(key, benign.text)) is None
    assert broker.consume("shell_exec", "rm -rf /srv", "c") is False


def test_broker_signed_arm_keeps_client_binding_and_expiry(tmp_path: Path) -> None:
    key = _key()
    broker, clock = _signed_broker(tmp_path, key)
    ch = broker.plan("shell_exec", "rm -rf /x", "client-a", describe=_describe)
    sig = _sign(key, ch.text)
    assert broker.arm_signed(ch.token, "client-b", sig) is None  # foreign client
    assert broker.check_signature(ch.token, "client-a", sig) == "operator@example"
    clock.t += 61
    assert broker.arm_signed(ch.token, "client-a", sig) is None  # expired
    assert broker.check_signature(ch.token, "client-a", sig) is None


def test_check_signature_does_not_arm(tmp_path: Path) -> None:
    key = _key()
    broker, _ = _signed_broker(tmp_path, key)
    ch = broker.plan("shell_exec", "rm -rf /x", "", describe=_describe)
    assert broker.check_signature(ch.token, "", _sign(key, ch.text)) == "operator@example"
    assert broker.consume("shell_exec", "rm -rf /x", "") is False


def test_client_mode_broker_is_unchanged() -> None:
    broker = ConfirmationBroker(60)
    assert not broker.requires_signature
    ch = broker.plan("shell_exec", "rm -rf /x", describe=_describe)
    assert ch.text == ""  # no challenge line without a verifier
    assert broker.arm_signed(ch.token, "", "sig") is None
    assert broker.arm(ch.token) is True


# --- settings ------------------------------------------------------------


def test_settings_validate_signature_approval(tmp_path: Path) -> None:
    base = {"audit_path": str(tmp_path / "a.jsonl"), "transport": "stdio"}
    with pytest.raises(ValueError, match="requires confirm_tier3=true"):
        Settings(**base, confirm_approval="signature", confirm_allowed_signers="/x")
    with pytest.raises(ValueError, match="requires confirm_allowed_signers"):
        Settings(**base, confirm_tier3=True, confirm_approval="signature")
    with pytest.raises(ValueError, match="confirm_approval must be one of"):
        Settings(**base, confirm_approval="operator")
    assert Settings(**base).confirm_approval == "client"


# --- server wiring -------------------------------------------------------


def _signed_settings(tmp_path: Path, signers: str) -> Settings:
    return Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory="",
        auth_state_dir=str(tmp_path / "oauth"),
        confirm_tier3=True,
        confirm_ttl=300,
        confirm_approval="signature",
        confirm_allowed_signers=signers,
    )


def _records(path: str) -> list[dict]:
    return [json.loads(ln) for ln in Path(path).read_text().splitlines() if ln.strip()]


def _plan(text: str) -> tuple[str, str]:
    token_m = re.search(r'token="([A-Za-z0-9_-]+)"', text)
    line = next((ln for ln in text.splitlines() if ln.startswith(CHALLENGE_PREFIX)), None)
    assert token_m and line, text
    return token_m.group(1), line


async def test_server_signed_approval_end_to_end(tmp_path: Path) -> None:
    key = _key()
    cfg = _signed_settings(tmp_path, _signers_file(tmp_path, ("operator@example", key)))
    mcp = build_server(cfg)
    victim = tmp_path / "victim.txt"
    victim.write_text("data")
    secret = "hunter2-" + "s3cr3t" * 3
    cmd = f"DB_PASSWORD={secret} rm -rf {victim}"

    r1 = _text((await mcp.call_tool("shell_exec", {"command": cmd})).content)
    assert "operator's signed approval" in r1 and "ssh-keygen -Y sign" in r1
    token, line = _plan(r1)
    assert secret not in line, "the challenge shows redacted arguments only"
    assert victim.exists()

    # The client alone cannot arm it, with or without a made-up signature.
    r2 = _text((await mcp.call_tool("operation_confirm", {"token": token})).content)
    assert "operator approval required" in r2
    forged = _sign(_key(), line)
    r3 = _text(
        (await mcp.call_tool("operation_confirm", {"token": token, "signature": forged})).content
    )
    assert "does not verify" in r3
    r4 = _text((await mcp.call_tool("shell_exec", {"command": cmd})).content)
    assert "CONFIRM REQUIRED" in r4 and victim.exists()

    # The operator signs the newest challenge; that arms exactly this call.
    token, line = _plan(r4)
    good = _sign(key, line + "\n")
    r5 = _text(
        (await mcp.call_tool("operation_confirm", {"token": token, "signature": good})).content
    )
    assert "armed by operator@example" in r5
    r6 = _text((await mcp.call_tool("shell_exec", {"command": cmd})).content)
    assert "CONFIRM REQUIRED" not in r6
    assert not victim.exists()

    recs = _records(cfg.audit_path)
    arms = [r for r in recs if r["tool"] == "operation_confirm"]
    assert [r["args"]["approver"] for r in arms] == ["", "", "operator@example"]
    assert all(len(r["args"]["token_sha256"]) == 12 for r in arms)
    raw = Path(cfg.audit_path).read_text()
    assert token not in raw and good.splitlines()[1] not in raw
    assert ("shell_exec", "confirm_execute") in [(r["tool"], r.get("action")) for r in recs]

    # A replayed signature does not arm the next plan of the same command.
    r7 = _text((await mcp.call_tool("shell_exec", {"command": f"rm -rf {victim}"})).content)
    token2, _ = _plan(r7)
    r8 = _text(
        (await mcp.call_tool("operation_confirm", {"token": token2, "signature": good})).content
    )
    assert "does not verify" in r8


async def test_server_info_reports_signers(tmp_path: Path) -> None:
    key = _key()
    cfg = _signed_settings(tmp_path, _signers_file(tmp_path, ("operator@example", key)))
    mcp = build_server(cfg)
    info = json.loads(_text((await mcp.call_tool("server_info", {})).content))
    confirm = info["config"]["confirm"] if "config" in info else info["confirm"]
    assert confirm["approval"] == "signature"
    assert confirm["signers"][0]["principal"] == "operator@example"
    assert confirm["signers"][0]["fingerprint"] == key.get_fingerprint("sha256")


def test_server_refuses_to_start_with_a_bad_signers_file(tmp_path: Path) -> None:
    path = tmp_path / "allowed_signers"
    path.write_text("operator@example ssh-ed25519 broken\n")
    os.chmod(path, 0o644)
    with pytest.raises(ValueError, match="allowed signers"):
        build_server(_signed_settings(tmp_path, str(path)))
