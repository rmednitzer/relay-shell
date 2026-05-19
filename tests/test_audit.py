from __future__ import annotations

import json
from pathlib import Path

from relay_shell.audit import AuditLogger
from relay_shell.util import sha256_hex


def test_audit_writes_jsonl_with_hash_not_body(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    assert log.degraded is False
    secret_output = "SECRET-BODY-12345"
    log.record(
        tool="shell_exec",
        args={"command": "echo hi"},
        output=secret_output,
        exit_code=0,
        tier=1,
        request_id="r1",
        client_id="c1",
    )
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["tool"] == "shell_exec"
    assert rec["exit_code"] == 0
    assert rec["tier"] == 1
    assert rec["request_id"] == "r1"
    assert rec["output_sha256"] == sha256_hex(secret_output)
    assert "SECRET-BODY" not in lines[0]  # body never written
    assert rec["output_len"] == len(secret_output.encode())


def test_audit_degrades_on_unwritable_path() -> None:
    log = AuditLogger("/proc/cannot/write/here/audit.jsonl")
    assert log.degraded is True
    # Must not raise even when degraded.
    log.record(tool="t", args={}, output="x", exit_code=None, tier=0)


def test_audit_records_denied_flag(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLogger(str(path))
    log.record(tool="shell_exec", args={}, output="[DENIED]", exit_code=None, tier=3, denied=True)
    rec = json.loads(path.read_text().strip())
    assert rec["denied"] is True
    assert rec["tier"] == 3
