from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "deploy/evidence/relay-audit-evidence-sync"


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
