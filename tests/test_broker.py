"""Tier-3 confirmation broker (ADR 0009): unit + server-wiring coverage.

Two layers:

* ``ConfirmationBroker`` unit tests drive plan/arm/consume directly with an
  injected clock so TTL expiry is deterministic (no sleeps).
* Wiring tests exercise the gate through ``build_server`` / ``call_tool``:
  the default-off path stays byte-identical (no ``action`` field, Tier-3 runs
  unchanged) and the opt-in path challenges then executes, with the raw token
  never reaching the audit log.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from relay_shell.broker import ConfirmationBroker
from relay_shell.config import Settings
from relay_shell.policy import Tier, classify
from relay_shell.server import build_server

# --- a controllable clock ---------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


# --- ConfirmationBroker unit tests ------------------------------------


def test_plan_arm_consume_happy_path() -> None:
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "shell_exec rm -rf /data")
    assert ch.ttl == 120 and ch.token
    # Not armed yet: consume must not release it.
    assert b.consume("shell_exec", "shell_exec rm -rf /data") is False
    assert b.arm(ch.token) is True
    assert b.consume("shell_exec", "shell_exec rm -rf /data") is True


def test_consume_is_single_use() -> None:
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "op-A")
    b.arm(ch.token)
    assert b.consume("shell_exec", "op-A") is True
    # Burned: a second identical call re-challenges (consume returns False).
    assert b.consume("shell_exec", "op-A") is False


def test_consume_requires_exact_operation() -> None:
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "rm -rf /a")
    b.arm(ch.token)
    # Same tool, different command -> different hash -> no match.
    assert b.consume("shell_exec", "rm -rf /b") is False
    # Same command, different tool -> no match either.
    assert b.consume("ssh_exec", "rm -rf /a") is False
    # Exact match still works.
    assert b.consume("shell_exec", "rm -rf /a") is True


def test_token_expires_before_arm() -> None:
    clock = _Clock()
    b = ConfirmationBroker(ttl=60, clock=clock)
    ch = b.plan("shell_exec", "op")
    clock.advance(61)
    assert b.arm(ch.token) is False
    assert b.consume("shell_exec", "op") is False


def test_token_expires_after_arm_before_consume() -> None:
    clock = _Clock()
    b = ConfirmationBroker(ttl=60, clock=clock)
    ch = b.plan("shell_exec", "op")
    assert b.arm(ch.token) is True
    clock.advance(61)
    assert b.consume("shell_exec", "op") is False


def test_arm_unknown_token() -> None:
    b = ConfirmationBroker(ttl=120)
    assert b.arm("not-a-real-token") is False


def test_arm_is_idempotent() -> None:
    b = ConfirmationBroker(ttl=120)
    ch = b.plan("shell_exec", "op")
    assert b.arm(ch.token) is True
    assert b.arm(ch.token) is True  # arming twice is not an error
    assert b.consume("shell_exec", "op") is True


def test_pending_reflects_live_tokens_and_sweeps() -> None:
    clock = _Clock()
    b = ConfirmationBroker(ttl=30, clock=clock)
    b.plan("shell_exec", "a")
    b.plan("shell_exec", "b")
    assert b.pending() == 2
    clock.advance(31)
    assert b.pending() == 0  # expired entries swept


def test_store_is_bounded() -> None:
    b = ConfirmationBroker(ttl=3600, max_pending=4)
    for i in range(50):
        b.plan("shell_exec", f"op-{i}")
    assert b.pending() <= 4


def test_ttl_floor() -> None:
    # A nonsensical sub-1 ttl is floored to 1, never zero/negative.
    assert ConfirmationBroker(ttl=0).ttl == 1


# --- server wiring: broker OFF (default) ------------------------------


def _records(path: str) -> list[dict]:
    p = Path(path)
    if not p.is_file():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


async def test_off_tier3_runs_and_record_has_no_action(settings: Settings) -> None:
    # Default settings: confirm_tier3 is False.
    assert settings.confirm_tier3 is False
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("shell_exec", {"command": "rm -rf /tmp/relay-nope-xyz"})
    text = "".join(b.text for b in content if getattr(b, "type", "") == "text")
    # It executed (no confirmation challenge) ...
    assert "CONFIRM REQUIRED" not in text
    recs = _records(settings.audit_path)
    assert recs and recs[-1]["tool"] == "shell_exec"
    # ... and the additive `action` field is absent -> record byte-identical.
    assert "action" not in recs[-1]


# --- server wiring: broker ON -----------------------------------------


def _on_settings(tmp_path: Path) -> Settings:
    return Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        policy_mode="open",
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        inventory="",
        auth_state_dir=str(tmp_path / "oauth"),
        confirm_tier3=True,
        confirm_ttl=120,
    )


def _text(content: object) -> str:
    return "".join(b.text for b in content if getattr(b, "type", "") == "text")  # type: ignore[attr-defined]


async def test_on_tier3_challenges_then_executes(tmp_path: Path) -> None:
    cfg = _on_settings(tmp_path)
    mcp = build_server(cfg)
    victim = tmp_path / "victim.txt"
    victim.write_text("data")
    cmd = f"rm -rf {victim}"

    # 1) plan: challenge returned, work() did NOT run (file still present).
    r1 = _text((await mcp.call_tool("shell_exec", {"command": cmd}))[0])
    assert "CONFIRM REQUIRED" in r1
    assert victim.exists(), "planned Tier-3 op must not execute"
    token = re.search(r'token="([A-Za-z0-9_-]+)"', r1).group(1)

    # 2) arm
    r2 = _text((await mcp.call_tool("operation_confirm", {"token": token}))[0])
    assert "armed" in r2

    # 3) execute: same call now runs (file removed).
    r3 = _text((await mcp.call_tool("shell_exec", {"command": cmd}))[0])
    assert "CONFIRM REQUIRED" not in r3
    assert not victim.exists(), "confirmed Tier-3 op must execute"

    # audit markers: confirm_plan on the challenge, confirm_execute on the run.
    recs = _records(cfg.audit_path)
    actions = [(r["tool"], r.get("action")) for r in recs]
    assert ("shell_exec", "confirm_plan") in actions
    assert ("shell_exec", "confirm_execute") in actions
    # single-use: a further identical call re-challenges.
    r4 = _text((await mcp.call_tool("shell_exec", {"command": cmd}))[0])
    assert "CONFIRM REQUIRED" in r4


async def test_on_bad_token_rechallenges(tmp_path: Path) -> None:
    cfg = _on_settings(tmp_path)
    mcp = build_server(cfg)
    cmd = "rm -rf /tmp/relay-nope-xyz"
    _text((await mcp.call_tool("shell_exec", {"command": cmd}))[0])  # plan
    r = _text((await mcp.call_tool("operation_confirm", {"token": "bogus-token"}))[0])
    assert "invalid or expired" in r
    # Still gated: an unarmed op is re-challenged.
    again = _text((await mcp.call_tool("shell_exec", {"command": cmd}))[0])
    assert "CONFIRM REQUIRED" in again


async def test_on_non_tier3_is_unaffected(tmp_path: Path) -> None:
    cfg = _on_settings(tmp_path)
    mcp = build_server(cfg)
    # A plain read/observe command is Tier 1, not gated even with broker on.
    r = _text((await mcp.call_tool("shell_exec", {"command": "echo ok"}))[0])
    assert "CONFIRM REQUIRED" not in r
    assert "ok" in r


async def test_operation_confirm_disabled_reports(settings: Settings) -> None:
    # Broker off -> operation_confirm reports disabled, changes nothing.
    mcp = build_server(settings)
    r = _text((await mcp.call_tool("operation_confirm", {"token": "x"}))[0])
    assert "disabled" in r


async def test_raw_token_never_written_to_audit(tmp_path: Path) -> None:
    cfg = _on_settings(tmp_path)
    mcp = build_server(cfg)
    cmd = "rm -rf /tmp/relay-nope-xyz"
    r1 = _text((await mcp.call_tool("shell_exec", {"command": cmd}))[0])
    token = re.search(r'token="([A-Za-z0-9_-]+)"', r1).group(1)
    await mcp.call_tool("operation_confirm", {"token": token})
    raw_audit = Path(cfg.audit_path).read_text()
    assert token not in raw_audit, "raw confirmation token must not reach the audit log"


async def test_on_token_bound_to_target_not_just_command(tmp_path: Path) -> None:
    # Regression (security review, 2026-07-15): the token must bind the full
    # audited argument set, not just the command text. `cwd` lives in audit_args
    # but NOT in policy_text, so a token armed for one cwd must NOT authorize the
    # same command against a different cwd (confused-deputy replay).
    cfg = _on_settings(tmp_path)
    mcp = build_server(cfg)
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "keep.txt").write_text("a")
    (dir_b / "keep.txt").write_text("b")
    cmd = "rm -rf ./keep.txt"

    # plan + arm for cwd=dir_a
    r1 = _text((await mcp.call_tool("shell_exec", {"command": cmd, "cwd": str(dir_a)}))[0])
    token = re.search(r'token="([A-Za-z0-9_-]+)"', r1).group(1)
    await mcp.call_tool("operation_confirm", {"token": token})

    # Attempt to execute the SAME command against cwd=dir_b: must re-challenge,
    # and dir_b must be untouched (the armed token does not match this target).
    r2 = _text((await mcp.call_tool("shell_exec", {"command": cmd, "cwd": str(dir_b)}))[0])
    assert "CONFIRM REQUIRED" in r2
    assert (dir_b / "keep.txt").exists(), "token for cwd=a must not authorize cwd=b"
    # The original target still executes (token still armed for cwd=a).
    r3 = _text((await mcp.call_tool("shell_exec", {"command": cmd, "cwd": str(dir_a)}))[0])
    assert "CONFIRM REQUIRED" not in r3
    assert not (dir_a / "keep.txt").exists()


def test_confirm_op_key_binds_ssh_identity() -> None:
    # F3 regression (2026-07-15): the broker op-key must bind the SSH
    # authenticating identity (user/port/key_path), which ssh_exec/ssh_spawn now
    # carry in audit_args — otherwise a token confirmed as a low-priv user could
    # be re-issued as root against the same host+command (confused deputy).
    from relay_shell.server import _confirm_op_key, _policy_text_ssh_exec

    pt = _policy_text_ssh_exec("db", "DROP DATABASE prod")

    def args(user: str, port: int, key: str) -> dict:
        return {
            "host": "db",
            "command": "DROP DATABASE prod",
            "timeout": 60,
            "user": user,
            "port": port,
            "key_path": key,
            "jump": "",
            "known_hosts": "strict",
        }

    base = _confirm_op_key(pt, args("readonly", 22, "/k/ro"))
    assert _confirm_op_key(pt, args("readonly", 22, "/k/ro")) == base  # stable
    assert _confirm_op_key(pt, args("root", 22, "/k/ro")) != base  # user swap
    assert _confirm_op_key(pt, args("readonly", 2222, "/k/ro")) != base  # port swap
    assert _confirm_op_key(pt, args("readonly", 22, "/k/root")) != base  # key swap


def test_operation_confirm_is_tier0() -> None:
    # Control-plane step: classified read-only so it is available in every mode.
    assert classify("operation_confirm") == Tier.READ_ONLY
