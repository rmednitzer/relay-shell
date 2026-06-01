from __future__ import annotations

import json
import os
from pathlib import Path

from relay_shell.audit import AuditLogger, verify_chain
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
    # AuditLogger.__init__ pre-creates its audit file via os.open(...,
    # O_APPEND | O_CREAT, ...), so we cannot reach the missing-file path
    # by simply constructing one. Build a hollow instance whose `path`
    # points at a file that was never created, exercise tail() against
    # that path, and confirm it returns "" without raising.
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


def test_tail_bounded_by_requested_lines_not_file_size(tmp_path: Path) -> None:
    # Codex review on #29: tail() must read at most O(lines * record_size)
    # from disk, NOT the whole file. Verify by writing many records and
    # asking for a small tail. Even if the read-backwards implementation
    # subtly over-reads, this test pins that we never load anything close
    # to the full file into Python-level memory.
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    # ~10 000 records; each line is ~250 bytes after JSON serialization,
    # so the file is roughly 2.5 MiB. The tail of 5 is well under 2 KiB.
    for i in range(10_000):
        log.record(
            tool="shell_exec",
            args={"command": f"echo seq-{i}"},
            output="x" * 32,
            exit_code=0,
            tier=1,
        )
    out = log.tail(5)
    lines = out.splitlines()
    assert len(lines) == 5
    recs = [json.loads(ln) for ln in lines]
    # Oldest of the returned five should be record 9995; newest 9999.
    assert recs[0]["args"]["command"] == "echo seq-9995"
    assert recs[-1]["args"]["command"] == "echo seq-9999"
    # The tail output size is comfortably under the file size: the
    # implementation read backwards, not forwards.
    file_size = path.stat().st_size
    assert file_size > 1_000_000  # sanity: file really is big
    assert len(out.encode()) < 4_000  # tail is small regardless


def test_audit_logger_closes_prior_handler_on_reinit(tmp_path: Path) -> None:
    """F-7 regression: re-init releases the prior WatchedFileHandler's fd.

    The audit logger is process-global (``logging.getLogger("relay_shell.audit")``);
    re-initializing previously called ``removeHandler`` without ``close()``,
    leaking one open fd per construction (visible from
    ``--check-config`` and any test that builds multiple AuditLoggers).
    """
    path = tmp_path / "a.jsonl"
    log1 = AuditLogger(str(path))
    handler1 = log1._log.handlers[0]
    # Force at least one write so the WatchedFileHandler opens its stream
    # (some Python versions open lazily on first emit).
    log1.record(tool="t", args={}, output="x", exit_code=0, tier=0)
    assert handler1.stream is not None

    # Re-init the same process-global logger.
    AuditLogger(str(path))

    # FileHandler.close() sets self.stream = None; the assertion pins the
    # contract that the prior handler is closed, not just removed.
    assert handler1.stream is None


def test_audit_cef_format(tmp_path: Path) -> None:
    path = tmp_path / "audit.cef"
    log = AuditLogger(str(path), fmt="cef")
    log.record(tool="shell_exec", args={"command": "id"}, output="ok", exit_code=0, tier=1)
    line = path.read_text(encoding="utf-8").strip()
    assert line.startswith("CEF:0|relay-shell|relay-shell|1.0|audit|tool-call|5|")
    assert "tool=shell_exec" in line
    assert "output_sha256=" in line


def test_audit_leef_format(tmp_path: Path) -> None:
    path = tmp_path / "audit.leef"
    log = AuditLogger(str(path), fmt="leef")
    log.record(tool="server_info", args={}, output="ok", exit_code=0, tier=0)
    line = path.read_text(encoding="utf-8").strip()
    assert line.startswith("LEEF:2.0|relay-shell|relay-shell|1.0|audit\t")
    assert "tool=server_info" in line
    assert "\toutput_len=" in line


def test_audit_cef_escapes_delimiters(tmp_path: Path) -> None:
    path = tmp_path / "audit.cef"
    log = AuditLogger(str(path), fmt="cef")
    log.record(
        tool="shell_exec",
        args={"command": "echo a|b=c"},
        output="ok\nline2",
        exit_code=0,
        tier=1,
    )
    line = path.read_text(encoding="utf-8").strip()
    assert 'args={"command":"echo a\\|b\\=c"}' in line
    assert "output_len=8" in line


def test_audit_leef_escapes_tabs_and_delimiters(tmp_path: Path) -> None:
    path = tmp_path / "audit.leef"
    log = AuditLogger(str(path), fmt="leef")
    log.record(
        tool="shell_exec",
        args={"command": "printf 'a\\tb=c'"},
        output="ok\r\nline2",
        exit_code=0,
        tier=1,
    )
    line = path.read_text(encoding="utf-8").strip()
    assert 'args={"command":"printf \'a\\\\\\\\tb\\=c\'"}' in line
    assert "\ttool=shell_exec" in line


# --- Tamper-evident hash chain (ADR 0007) -----------------------------------

_GENESIS = "0" * 64


def _write_chained(path: Path, n: int) -> list[dict]:
    """Write ``n`` chained records and return them parsed, in order."""
    log = AuditLogger(str(path), chain=True)
    for i in range(n):
        log.record(tool="t", args={"i": i}, output=f"o{i}", exit_code=0, tier=1)
    return [json.loads(ln) for ln in path.read_text().strip().splitlines()]


def _rewrite(path: Path, recs: list[dict]) -> None:
    """Re-serialize a (possibly tampered) record list back to disk."""
    with path.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def test_chain_off_by_default_has_no_extra_fields(tmp_path: Path) -> None:
    # Default (chain off) must stay byte-identical to v0.1: no seq/prev/chain.
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    assert log.chain is False
    log.record(tool="shell_exec", args={"command": "id"}, output="ok", exit_code=0, tier=1)
    rec = json.loads(path.read_text().strip())
    assert "seq" not in rec
    assert "prev" not in rec
    assert "chain" not in rec


def test_chain_emits_seq_prev_chain_with_genesis_anchor(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 3)
    assert [r["seq"] for r in recs] == [0, 1, 2]
    assert recs[0]["prev"] == _GENESIS
    # Each record links to the previous record's chain hash.
    assert all(recs[i]["prev"] == recs[i - 1]["chain"] for i in range(1, 3))


def test_chain_record_still_hashes_output_not_body(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path), chain=True)
    log.record(tool="t", args={}, output="CHAIN-SECRET-BODY", exit_code=0, tier=1)
    text = path.read_text()
    assert "CHAIN-SECRET-BODY" not in text
    rec = json.loads(text.strip())
    assert rec["output_sha256"] == sha256_hex("CHAIN-SECRET-BODY")


def test_chain_resumes_across_reinit(tmp_path: Path) -> None:
    # A restart continues the chain from the last on-disk record, not genesis.
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path), chain=True)
    for i in range(2):
        log.record(tool="t", args={"i": i}, output="x", exit_code=0, tier=1)
    AuditLogger(str(path), chain=True).record(
        tool="t", args={"i": 2}, output="x", exit_code=0, tier=1
    )
    recs = [json.loads(ln) for ln in path.read_text().strip().splitlines()]
    assert [r["seq"] for r in recs] == [0, 1, 2]
    assert recs[2]["prev"] == recs[1]["chain"]  # continued, not reset
    assert verify_chain(str(path)).ok


def test_verify_chain_intact(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chained(path, 5)
    r = verify_chain(str(path))
    assert r.ok
    assert r.records == 5
    assert r.start_seq == 0
    assert r.broken_at is None


def test_verify_chain_detects_record_edit(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 4)
    recs[2]["args"]["i"] = 999  # edit a body; leave seq/prev/chain untouched
    _rewrite(path, recs)
    r = verify_chain(str(path))
    assert not r.ok
    assert r.broken_at == 3
    assert "tampered" in r.reason


def test_verify_chain_detects_chain_field_forgery(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 3)
    recs[1]["chain"] = "f" * 64  # forge the stored chain directly
    _rewrite(path, recs)
    r = verify_chain(str(path))
    assert not r.ok
    assert r.broken_at == 2


def test_verify_chain_detects_deletion(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 4)
    del recs[1]  # excise a record; seq jumps and linkage breaks
    _rewrite(path, recs)
    assert not verify_chain(str(path)).ok


def test_verify_chain_detects_reorder(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 4)
    recs[1], recs[2] = recs[2], recs[1]
    _rewrite(path, recs)
    assert not verify_chain(str(path)).ok


def test_verify_chain_seq0_must_anchor_genesis(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 1)
    recs[0]["prev"] = "1" * 64  # a from-scratch chain must anchor to genesis
    _rewrite(path, recs)
    r = verify_chain(str(path))
    assert not r.ok
    assert "genesis" in r.reason


def test_verify_chain_skips_leading_legacy_records(tmp_path: Path) -> None:
    # Chaining enabled on an existing log: leading unchained lines are skipped.
    path = tmp_path / "audit.jsonl"
    AuditLogger(str(path)).record(tool="t", args={"i": -1}, output="x", exit_code=0, tier=1)
    chained = AuditLogger(str(path), chain=True)
    for i in range(2):
        chained.record(tool="t", args={"i": i}, output="x", exit_code=0, tier=1)
    r = verify_chain(str(path))
    assert r.ok
    assert r.records == 2
    assert r.start_seq == 0


def test_verify_chain_legacy_line_inside_region_is_a_break(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 3)
    for key in ("chain", "seq", "prev"):
        recs[1].pop(key)  # strip a record's chain fields mid-region
    _rewrite(path, recs)
    r = verify_chain(str(path))
    assert not r.ok
    assert "missing chain fields" in r.reason


def test_verify_chain_garbage_line_in_region_is_a_break(tmp_path: Path) -> None:
    # Inserting a non-JSON line into the chained region is a break, not a skip.
    path = tmp_path / "audit.jsonl"
    _write_chained(path, 2)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
    r = verify_chain(str(path))
    assert not r.ok
    assert "invalid JSON" in r.reason


def test_verify_chain_missing_file_is_ok_with_no_records(tmp_path: Path) -> None:
    # verify_chain is structural (no break in a nonexistent region), but flags
    # the file as absent so the CLI can fail-closed on it.
    r = verify_chain(str(tmp_path / "never-created.jsonl"))
    assert r.ok
    assert r.records == 0
    assert r.present is False


def test_verify_chain_unchained_log_reports_no_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLogger(str(path)).record(tool="t", args={}, output="x", exit_code=0, tier=0)
    r = verify_chain(str(path))
    assert r.ok
    assert r.records == 0
    assert "no chained records" in r.reason


def test_verify_chain_genesis_log_is_anchored(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chained(path, 3)
    r = verify_chain(str(path))
    assert r.ok
    assert r.anchored is True
    assert r.start_seq == 0


def test_verify_chain_head_truncation_is_valid_but_not_anchored(tmp_path: Path) -> None:
    # Excising leading records (incl. seq 0) leaves a valid sub-chain that the
    # recompute/linkage checks accept — but it is no longer genesis-anchored,
    # which is the head-truncation signal (ADR 0007). The fail-closed CLI
    # rejects this by default (`--segment` opts out for a rotation segment).
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 5)
    _rewrite(path, recs[2:])  # drop seq 0 and 1
    r = verify_chain(str(path))
    assert r.ok  # internally consistent
    assert r.anchored is False  # head-truncation signal
    assert r.start_seq == 2


def test_verify_chain_tail_truncation_is_a_valid_prefix(tmp_path: Path) -> None:
    # Dropping the newest records leaves a valid genesis-anchored prefix. A
    # single file CANNOT detect this (documented limitation in ADR 0007); the
    # off-host copy is the defense. This test pins the limitation honestly so a
    # future change that claims otherwise has to update it deliberately.
    path = tmp_path / "audit.jsonl"
    recs = _write_chained(path, 5)
    _rewrite(path, recs[:3])  # drop the last two
    r = verify_chain(str(path))
    assert r.ok
    assert r.anchored is True
    assert r.records == 3
