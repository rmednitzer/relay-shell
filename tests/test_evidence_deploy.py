from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

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


def _run_verifier(log_dir: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
    env = {
        **os.environ,
        "RELAY_AUDIT_LOG_DIR": str(log_dir),
        "RELAY_AUDIT_APPROVALS": str(log_dir / "no-approvals.json"),
    }
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
