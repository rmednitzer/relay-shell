from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "deploy/evidence/relay-audit-evidence-sync"
VERIFIER = Path(__file__).parents[1] / "deploy/evidence/relay-audit-evidence.py"
GENESIS = "0" * 64


def _load_verifier() -> Any:
    """Import the verifier script as a module to reuse its exact chain hashing."""
    spec = importlib.util.spec_from_file_location("relay_audit_evidence", VERIFIER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_VERIFIER_MOD = _load_verifier()


def _record(seq: int, prev: str, ts: str) -> dict[str, Any]:
    """A valid chained audit record whose `chain` matches the verifier's hash."""
    row: dict[str, Any] = {"ts": ts, "tool": "shell_exec", "tier": 1, "seq": seq, "prev": prev}
    row["chain"] = _VERIFIER_MOD.canonical_chain(prev, row)
    return row


def _write_segment(
    path: Path, records: list[dict[str, Any]], *, trailing_newline: bool = True
) -> None:
    body = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records)
    if not trailing_newline and body.endswith("\n"):
        body = body[:-1]
    path.write_text(body, encoding="utf-8")


def _run_verifier(
    log_dir: Path,
    *,
    retain: int | None = None,
    approvals: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
    env = {
        **os.environ,
        "RELAY_AUDIT_LOG_DIR": str(log_dir),
        "RELAY_AUDIT_APPROVALS": str(approvals or log_dir / "no-approvals.json"),
    }
    if retain is not None:
        env["RELAY_AUDIT_RETAIN_SEGMENTS"] = str(retain)
    result = subprocess.run(
        [sys.executable, str(VERIFIER)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    evidence_file = log_dir / "chain-verification.jsonl"
    evidence = None
    if evidence_file.exists():
        evidence = json.loads(evidence_file.read_text(encoding="utf-8").splitlines()[-1])
    return result, evidence


def _executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _run_sync(
    tmp_path: Path,
    *,
    verify_status: int = 0,
    fail_rsync_call: int = 0,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    verifier = tmp_path / "verify"
    rsync = tmp_path / "rsync"
    log = tmp_path / "rsync.log"
    count = tmp_path / "rsync.count"
    _executable(verifier, '#!/bin/sh\nexit "${FAKE_VERIFY_STATUS:-0}"\n')
    _executable(
        rsync,
        """#!/bin/sh
set -eu
n=0
[ ! -f "$FAKE_RSYNC_COUNT" ] || n=$(cat "$FAKE_RSYNC_COUNT")
n=$((n + 1))
printf '%s\n' "$n" > "$FAKE_RSYNC_COUNT"
{
  printf 'CALL\n'
  printf '%s\n' "$@"
  printf 'END\n'
} >> "$FAKE_RSYNC_LOG"
[ "${FAKE_RSYNC_FAIL_CALL:-0}" -ne "$n" ] || exit 23
""",
    )
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "RELAY_AUDIT_LOG_DIR": str(evidence_dir),
        "RELAY_AUDIT_RSYNC_DEST": "test.invalid:/evidence/",
        "RELAY_AUDIT_SSH_KNOWN_HOSTS": str(tmp_path / "known_hosts"),
        "RELAY_AUDIT_VERIFY_BIN": str(verifier),
        "RELAY_AUDIT_RSYNC_BIN": str(rsync),
        "FAKE_VERIFY_STATUS": str(verify_status),
        "FAKE_RSYNC_FAIL_CALL": str(fail_rsync_call),
        "FAKE_RSYNC_LOG": str(log),
        "FAKE_RSYNC_COUNT": str(count),
    }
    result = subprocess.run(
        [str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    return result, log, count


def _calls(log: Path) -> list[list[str]]:
    blocks = log.read_text(encoding="utf-8").split("CALL\n")[1:]
    return [block.split("END\n", 1)[0].splitlines() for block in blocks]


def test_sync_publishes_payload_before_anchor(tmp_path: Path) -> None:
    result, log, count = _run_sync(tmp_path)

    assert result.returncode == 0, result.stderr
    assert count.read_text(encoding="utf-8").strip() == "2"
    payload, anchor = _calls(log)
    assert "--delay-updates" in payload
    assert "--include=audit.jsonl*" in payload
    assert "--include=chain-verification.jsonl" in payload
    assert "--include=retained-checkpoints.json" in payload
    assert "--include=latest-anchor.json" not in payload
    assert "--delay-updates" in anchor
    assert "--include=latest-anchor.json" in anchor
    assert "--include=audit.jsonl*" not in anchor


def test_sync_publishes_nothing_when_verification_fails(tmp_path: Path) -> None:
    result, log, count = _run_sync(tmp_path, verify_status=7)

    assert result.returncode == 7
    assert not log.exists()
    assert not count.exists()


def test_sync_does_not_publish_anchor_when_payload_fails(tmp_path: Path) -> None:
    result, log, count = _run_sync(tmp_path, fail_rsync_call=1)

    assert result.returncode == 23
    assert count.read_text(encoding="utf-8").strip() == "1"
    assert len(_calls(log)) == 1


def test_sync_reports_failure_when_anchor_publish_fails(tmp_path: Path) -> None:
    result, log, count = _run_sync(tmp_path, fail_rsync_call=2)

    assert result.returncode == 23
    assert count.read_text(encoding="utf-8").strip() == "2"
    assert len(_calls(log)) == 2


# --- EVID-1: verifier segment ordering + torn-write tolerance ---


def test_verifier_orders_segments_by_record_ts_not_mtime(tmp_path: Path) -> None:
    """A rotated segment whose file mtime is NEWER than the live segment (as
    logrotate `delaycompress` produces when it compresses on a later cycle) must
    not break the seam check: ordering follows the record `ts`, not mtime.

    Regression for EVID-1: the pre-fix mtime sort would place the live segment
    (seq 2..3) before the rotated one (seq 0..1) and report a broken rotation
    seam, failing the run and silently suppressing the off-host sync.
    """
    r0 = _record(0, GENESIS, "2026-08-04T10:00:00+00:00")
    r1 = _record(1, r0["chain"], "2026-08-04T10:01:00+00:00")
    r2 = _record(2, r1["chain"], "2026-08-04T11:00:00+00:00")
    r3 = _record(3, r2["chain"], "2026-08-04T11:01:00+00:00")

    rotated = tmp_path / "audit.jsonl-20260804"
    active = tmp_path / "audit.jsonl"
    _write_segment(rotated, [r0, r1])
    _write_segment(active, [r2, r3])

    # Invert mtimes: the rotated (older, seq 0..1) file gets the NEWER mtime,
    # exactly the delaycompress inversion. A mtime sort would misorder them.
    os.utime(active, (1_000_000, 1_000_000))
    os.utime(rotated, (2_000_000, 2_000_000))

    result, evidence = _run_verifier(tmp_path)

    assert result.returncode == 0, f"stderr={result.stderr}"
    assert evidence is not None
    assert evidence["valid"] is True, evidence["errors"]
    assert evidence["records"] == 4
    assert not any("seam" in e for e in evidence["errors"])
    # Summary is emitted in chain order regardless of mtime.
    assert [s["first_seq"] for s in evidence["segment_summary"]] == [0, 2]


def test_verifier_tolerates_torn_final_line_on_active_segment(tmp_path: Path) -> None:
    """A torn (partial) final record on the LIVE segment — the signature of a
    read racing an in-progress append — is tolerated, not a hard failure."""
    r0 = _record(0, GENESIS, "2026-08-04T10:00:00+00:00")
    r1 = _record(1, r0["chain"], "2026-08-04T10:01:00+00:00")
    active = tmp_path / "audit.jsonl"
    _write_segment(active, [r0, r1])
    # Append a torn record: a valid-JSON prefix, no closing brace, no newline.
    with active.open("a", encoding="utf-8") as fh:
        fh.write('{"ts":"2026-08-04T10:02:00+00:00","tool":"shell_exec","tier":1,"seq":2')

    result, evidence = _run_verifier(tmp_path)

    assert result.returncode == 0, f"stderr={result.stderr}"
    assert evidence is not None
    assert evidence["valid"] is True, evidence["errors"]
    assert evidence["torn_tails"] == 1
    assert evidence["records"] == 2  # only the two complete records counted


def test_verifier_flags_malformed_line_that_is_not_the_tail(tmp_path: Path) -> None:
    """A parse failure that is NOT the final line is real corruption, not a torn
    append — it must fail the run even on the active segment."""
    r0 = _record(0, GENESIS, "2026-08-04T10:00:00+00:00")
    r1 = _record(1, r0["chain"], "2026-08-04T10:02:00+00:00")
    active = tmp_path / "audit.jsonl"
    # A garbage line sits BETWEEN two valid records (a following line exists),
    # so it cannot be a torn trailing append.
    body = (
        json.dumps(r0, separators=(",", ":"))
        + "\n"
        + '{"torn":"prefix-with-no-close"\n'
        + json.dumps(r1, separators=(",", ":"))
        + "\n"
    )
    active.write_text(body, encoding="utf-8")

    result, evidence = _run_verifier(tmp_path)

    assert result.returncode != 0
    assert evidence is not None
    assert evidence["valid"] is False
    assert evidence["torn_tails"] == 0
    assert any("invalid JSON" in e for e in evidence["errors"])


def test_verifier_does_not_tolerate_torn_tail_on_rotated_segment(tmp_path: Path) -> None:
    """Only the live segment may present a torn tail. A missing-newline / partial
    final line on a ROTATED segment is genuine truncation and must be flagged."""
    r0 = _record(0, GENESIS, "2026-08-04T10:00:00+00:00")
    rotated = tmp_path / "audit.jsonl-1"
    body = json.dumps(r0, separators=(",", ":")) + "\n" + '{"torn":"partial-no-newline"'
    rotated.write_text(body, encoding="utf-8")

    result, evidence = _run_verifier(tmp_path)

    assert result.returncode != 0
    assert evidence is not None
    assert evidence["valid"] is False
    assert evidence["torn_tails"] == 0
    assert any("invalid JSON" in e for e in evidence["errors"])


# --- A14-D3: retention pruning must not stall the evidence pipeline ---------


def _chain(count: int, *, start_seq: int = 0, prev: str = GENESIS) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i in range(count):
        seq = start_seq + i
        row = _record(seq, prev, f"2026-01-{seq + 1:02d}T00:00:00+00:00")
        rows.append(row)
        prev = row["chain"]
    return rows


def _rotated_history(log_dir: Path, segments: int = 4) -> list[list[dict[str, Any]]]:
    """``segments`` rotated files of 2 records each (oldest = ``audit.jsonl.<n>``) plus an
    active ``audit.jsonl``, all one continuous genesis-anchored chain."""
    rows = _chain((segments + 1) * 2)
    parts = [rows[i : i + 2] for i in range(0, len(rows), 2)]
    for index, part in enumerate(parts[:-1]):
        _write_segment(log_dir / f"audit.jsonl.{segments - index}", part)
    _write_segment(log_dir / "audit.jsonl", parts[-1])
    return parts


def test_verifier_accepts_rotation_pruning_after_a_checkpointed_run(tmp_path: Path) -> None:
    _rotated_history(tmp_path, segments=4)
    first, evidence = _run_verifier(tmp_path, retain=3)
    assert first.returncode == 0, first.stderr
    assert evidence is not None and evidence["retention_pruned_head"] is None
    assert (tmp_path / "retained-checkpoints.json").is_file()

    # logrotate drops the oldest rotated segment (rotate 3 keeps three).
    (tmp_path / "audit.jsonl.4").unlink()
    result, evidence = _run_verifier(tmp_path, retain=3)
    assert result.returncode == 0, result.stderr
    assert evidence is not None and evidence["valid"] is True
    assert evidence["retention_pruned_head"] == "checkpoint"
    assert evidence["first_retained_seq"] == 2
    assert evidence["latest_epoch"] is not None  # carried over from the checkpoint


def test_verifier_rejects_head_deletion_beyond_the_retention_window(tmp_path: Path) -> None:
    _rotated_history(tmp_path, segments=4)
    assert _run_verifier(tmp_path, retain=3)[0].returncode == 0
    # An attacker (or fault) removes one segment MORE than logrotate would have.
    (tmp_path / "audit.jsonl.4").unlink()
    (tmp_path / "audit.jsonl.3").unlink()
    result, evidence = _run_verifier(tmp_path, retain=3)
    assert result.returncode == 1
    assert evidence is not None and evidence["valid"] is False
    assert (
        "not genesis-anchored" in result.stderr and "2 rotated segments retained" in result.stderr
    )


def test_verifier_rejects_a_non_genesis_head_without_a_checkpoint(tmp_path: Path) -> None:
    parts = _rotated_history(tmp_path, segments=4)
    (tmp_path / "audit.jsonl.4").unlink()
    result, evidence = _run_verifier(tmp_path, retain=3)  # no earlier valid run
    assert result.returncode == 1
    assert evidence is not None and evidence["valid"] is False
    assert "approved_heads" in result.stderr
    assert parts[1][0]["prev"] in result.stderr  # the exact values an operator must review


def test_verifier_rejects_a_head_that_continues_an_unknown_chain(tmp_path: Path) -> None:
    _rotated_history(tmp_path, segments=4)
    assert _run_verifier(tmp_path, retain=3)[0].returncode == 0
    (tmp_path / "audit.jsonl.4").unlink()
    # Replace the new oldest segment with one that continues a DIFFERENT history.
    foreign = _chain(2, start_seq=2, prev="f" * 64)
    _write_segment(tmp_path / "audit.jsonl.3", foreign)
    result, _ = _run_verifier(tmp_path, retain=3)
    assert result.returncode == 1


def test_verifier_ignores_a_corrupt_checkpoint_file_and_fails_closed(tmp_path: Path) -> None:
    _rotated_history(tmp_path, segments=4)
    assert _run_verifier(tmp_path, retain=3)[0].returncode == 0
    (tmp_path / "audit.jsonl.4").unlink()
    (tmp_path / "retained-checkpoints.json").write_text("{not json", encoding="utf-8")
    result, evidence = _run_verifier(tmp_path, retain=3)
    assert result.returncode == 1
    assert "ignoring unreadable checkpoint file" in result.stderr
    assert evidence is not None and evidence["valid"] is False


def test_verifier_does_not_checkpoint_an_invalid_run(tmp_path: Path) -> None:
    rows = _chain(4)
    rows[2]["chain"] = "0" * 63 + "1"  # break the hash
    _write_segment(tmp_path / "audit.jsonl", rows)
    result, _ = _run_verifier(tmp_path)
    assert result.returncode == 1
    assert not (tmp_path / "retained-checkpoints.json").exists()


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="ledger must be root-owned")
def test_verifier_accepts_a_root_approved_pruned_head(tmp_path: Path) -> None:
    # Bootstrap for hosts that crossed the retention window before checkpoints existed.
    parts = _rotated_history(tmp_path, segments=4)
    (tmp_path / "audit.jsonl.4").unlink()
    head = parts[1][0]
    ledger = tmp_path / "approvals.json"
    ledger.write_text(
        json.dumps(
            {
                "version": 1,
                "approved_resets": [],
                "approved_heads": [
                    {
                        "first_seq": head["seq"],
                        "prev": head["prev"],
                        "approved_at": "2026-02-01T00:00:00+00:00",
                        "reason": "Reviewed: oldest segment rotated out pre-checkpoints.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    ledger.chmod(0o644)
    result, evidence = _run_verifier(tmp_path, retain=3, approvals=ledger)
    assert result.returncode == 0, result.stderr
    assert evidence is not None and evidence["retention_pruned_head"] == "approved"

    # A different (seq, prev) is not covered by that approval.
    (tmp_path / "audit.jsonl.3").unlink()
    result, _ = _run_verifier(tmp_path, retain=3, approvals=ledger)
    assert result.returncode == 1


@pytest.mark.parametrize("value", ["abc", "", "0", "-3", "3661", "1.5"])
def test_verifier_rejects_malformed_retention_values(tmp_path: Path, value: str) -> None:
    # The setting decides whether a non-genesis history is trusted: never coerce it.
    _write_segment(tmp_path / "audit.jsonl", _chain(2))
    env = {
        **os.environ,
        "RELAY_AUDIT_LOG_DIR": str(tmp_path),
        "RELAY_AUDIT_APPROVALS": str(tmp_path / "none.json"),
        "RELAY_AUDIT_RETAIN_SEGMENTS": value,
    }
    result = subprocess.run(
        [sys.executable, str(VERIFIER)], check=False, capture_output=True, text=True, env=env
    )
    assert result.returncode == 1
    assert "RELAY_AUDIT_RETAIN_SEGMENTS must be" in result.stderr
    assert not (tmp_path / "retained-checkpoints.json").exists()


def test_verifier_fails_when_checkpoints_cannot_be_persisted(tmp_path: Path) -> None:
    # Publishing a "valid" anchor that recorded no checkpoint would stall the pipeline
    # for good once logrotate removes the genesis segment; fail loudly instead.
    _write_segment(tmp_path / "audit.jsonl", _chain(3))
    (tmp_path / "retained-checkpoints.tmp").mkdir()  # blocks the atomic write
    result, evidence = _run_verifier(tmp_path)
    assert result.returncode == 1
    assert "could not write" in result.stderr
    assert evidence is not None and evidence["valid"] is False


def test_checkpoint_history_scales_with_the_retention_window(tmp_path: Path) -> None:
    env = {"RELAY_AUDIT_RETAIN_SEGMENTS": "1000", "RELAY_AUDIT_LOG_DIR": str(tmp_path)}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        module = _load_verifier()
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    assert module.RETAIN_SEGMENTS == 1000
    assert module.MAX_CHECKPOINTS >= 1001  # every endpoint of a full window plus the active one


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="ledger must be root-owned")
def test_approved_head_can_carry_the_chain_epoch(tmp_path: Path) -> None:
    parts = _rotated_history(tmp_path, segments=4)
    (tmp_path / "audit.jsonl.4").unlink()
    head = parts[1][0]
    epoch = "ab" * 32

    def _ledger(extra: dict[str, Any]) -> Path:
        path = tmp_path / "approvals.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "approved_resets": [],
                    "approved_heads": [
                        {
                            "first_seq": head["seq"],
                            "prev": head["prev"],
                            "approved_at": "2026-02-01T00:00:00+00:00",
                            "reason": "Reviewed pre-checkpoint rotation.",
                            **extra,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o644)
        return path

    result, evidence = _run_verifier(tmp_path, retain=3, approvals=_ledger({"epoch": epoch}))
    assert result.returncode == 0, result.stderr
    assert evidence is not None and evidence["latest_epoch"] == epoch
    saved = json.loads((tmp_path / "retained-checkpoints.json").read_text(encoding="utf-8"))
    assert all(entry["epoch"] == epoch for entry in saved["checkpoints"])

    # A malformed epoch invalidates the ledger (fail closed).
    result, _ = _run_verifier(tmp_path, retain=3, approvals=_ledger({"epoch": "not-hex"}))
    assert result.returncode == 1 and "epoch must be 64 lowercase hex" in result.stderr
