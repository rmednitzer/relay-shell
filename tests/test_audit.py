from __future__ import annotations

import json
import os
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


def test_audit_precreate_uses_o_append(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    real_open = os.open
    seen_append = False

    def wrapped_open(file: str, flags: int, mode: int = 0o777) -> int:
        nonlocal seen_append
        if file == str(path) and (flags & os.O_CREAT):
            seen_append = bool(flags & os.O_APPEND)
        return real_open(file, flags, mode)

    monkeypatch.setattr("relay_shell.audit.os.open", wrapped_open)
    log = AuditLogger(str(path))
    assert log.degraded is False
    assert seen_append is True


def test_tail_returns_last_n_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    for i in range(10):
        log.record(tool="shell_exec", args={"i": i}, output="ok", exit_code=0, tier=1)

    out = log.tail(3)
    lines = out.splitlines()
    assert len(lines) == 3
    # Oldest first; last record has i=9.
    recs = [json.loads(ln) for ln in lines]
    assert [r["args"]["i"] for r in recs] == [7, 8, 9]


def test_tail_returns_all_when_lines_exceeds_record_count(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    for i in range(3):
        log.record(tool="t", args={"i": i}, output="", exit_code=0, tier=0)
    assert len(log.tail(100).splitlines()) == 3


def test_tail_returns_empty_when_file_missing(tmp_path: Path) -> None:
    # The audit file is created lazily by AuditLogger.__init__ today, so use
    # a path the constructor never touches: ask tail() about a sibling
    # file that does not exist.
    log = AuditLogger(str(tmp_path / "a.jsonl"))
    other = AuditLogger.__new__(AuditLogger)
    other.path = str(tmp_path / "never-created.jsonl")
    other.degraded = False
    other.degraded_reason = ""
    # tail() on the path that does not exist must return "" without raising.
    assert other.tail(10) == ""
    # And the real instance with zero records must also return "".
    assert log.tail(10) == ""


def test_tail_rejects_non_positive_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    log.record(tool="t", args={}, output="", exit_code=0, tier=0)
    assert log.tail(0) == ""
    assert log.tail(-5) == ""


def test_tail_does_not_leak_output_body(tmp_path: Path) -> None:
    # Output bodies are never written to the audit log, so they cannot
    # show up here. Belt-and-braces regression: confirm at the tail()
    # layer (not just record()) since this tool exposes the log to a
    # caller that may itself be untrusted.
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    log.record(
        tool="shell_exec",
        args={"command": "echo hi"},
        output="VERY-SECRET-BODY-MARKER",
        exit_code=0,
        tier=1,
    )
    assert "VERY-SECRET-BODY-MARKER" not in log.tail(5)
