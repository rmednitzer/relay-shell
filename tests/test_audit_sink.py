"""Audit sinks must not mutate devices, hang on FIFOs, or hide reopen failure."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from relay_shell.audit import AuditLogger


@pytest.mark.parametrize("symlink", [False, True])
def test_device_sink_never_attempts_permission_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, symlink: bool
) -> None:
    device = Path("/dev/null")
    path = tmp_path / "device" if symlink else device
    if symlink:
        path.symlink_to(device)
    before = device.stat()
    real_chmod = Path.chmod
    real_fchmod = os.fchmod

    def guard_path_chmod(self: Path, mode: int, *args, **kwargs) -> None:
        assert self.resolve() != device, "permission change attempted on a device"
        real_chmod(self, mode, *args, **kwargs)

    def guard_fchmod(fd: int, mode: int) -> None:
        assert stat.S_ISREG(os.fstat(fd).st_mode), "fchmod attempted on a nonregular sink"
        real_fchmod(fd, mode)

    monkeypatch.setattr(Path, "chmod", guard_path_chmod)
    monkeypatch.setattr(os, "fchmod", guard_fchmod)
    log = AuditLogger(str(path), chain=True)
    assert log.degraded
    assert "regular file" in log.degraded_reason
    log.record(tool="test", args={}, output="synthetic", exit_code=0, tier=0)
    after = device.stat()
    assert (after.st_mode, after.st_rdev, after.st_uid, after.st_gid) == (
        before.st_mode,
        before.st_rdev,
        before.st_uid,
        before.st_gid,
    )


def test_existing_regular_sink_is_hardened_and_appended(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("existing\n")
    path.chmod(0o644)
    log = AuditLogger(str(path))
    assert not log.degraded
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    log.record(tool="test", args={}, output="synthetic", exit_code=0, tier=0)
    assert path.read_text().startswith("existing\n")


@pytest.mark.parametrize("reader", [False, True])
def test_fifo_initialization_is_bounded_and_preserves_mode(tmp_path: Path, reader: bool) -> None:
    path = tmp_path / "audit.fifo"
    os.mkfifo(path, 0o640)
    path.chmod(0o640)
    code = """
import json,os,sys
from relay_shell.audit import AuditLogger
reader = os.open(sys.argv[1], os.O_RDONLY | os.O_NONBLOCK) if sys.argv[2] == '1' else None
log = AuditLogger(sys.argv[1], chain=True)
log.record(tool='test',args={},output='synthetic',exit_code=0,tier=0)
print(json.dumps({'degraded':log.degraded}))
if reader is not None:os.close(reader)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path), str(int(reader))],
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    assert json.loads(result.stdout)["degraded"] is True
    assert stat.S_ISFIFO(path.stat().st_mode)
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_rotation_to_fifo_is_bounded_and_reported(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    code = """
import json,os,sys
from pathlib import Path
from relay_shell.audit import AuditLogger
path=Path(sys.argv[1]);log=AuditLogger(str(path),chain=True)
log.record(tool='before',args={},output='synthetic',exit_code=0,tier=0)
path.rename(str(path)+'.old')
os.mkfifo(path,0o640);path.chmod(0o640)
log.record(tool='after',args={},output='synthetic',exit_code=0,tier=0)
print(json.dumps({'degraded':log.degraded,'reason':log.degraded_reason}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)],
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    assert json.loads(result.stdout)["degraded"] is True
    assert "runtime" in json.loads(result.stdout)["reason"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


@pytest.mark.parametrize("earlier_gap", [False, True])
def test_rotation_to_device_is_reported(tmp_path: Path, earlier_gap: bool) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path), chain=True)
    log.record(tool="before", args={}, output="synthetic", exit_code=0, tier=0)
    path.rename(tmp_path / "audit.old")
    path.symlink_to("/dev/null")
    if earlier_gap:
        log.mark_degraded("earlier gap")
    log.record(tool="after", args={}, output="synthetic", exit_code=0, tier=0)
    assert log.degraded
    if earlier_gap:
        assert log.degraded_reason == "earlier gap"
    else:
        assert "runtime" in log.degraded_reason


def test_rotation_preserves_operator_created_file_mode(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path))
    log.record(tool="before", args={}, output="synthetic", exit_code=0, tier=0)
    path.rename(tmp_path / "audit.old")
    path.write_text("")
    path.chmod(0o640)
    log.record(tool="after", args={}, output="synthetic", exit_code=0, tier=0)
    assert not log.degraded
    assert json.loads(path.read_text())["tool"] == "after"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_hardening_uses_open_descriptor_during_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    moved = tmp_path / "original"
    path.write_text("")
    path.chmod(0o644)
    real_open = os.open
    replaced = False

    def replace_after_open(file: str, flags: int, mode: int = 0o777) -> int:
        nonlocal replaced
        fd = real_open(file, flags, mode)
        if file == str(path) and not replaced:
            replaced = True
            path.rename(moved)
            path.write_text("")
            path.chmod(0o644)
        return fd

    monkeypatch.setattr(os, "open", replace_after_open)
    log = AuditLogger(str(path))
    assert not log.degraded
    assert stat.S_IMODE(moved.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_rejected_sink_closes_open_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    device = "/dev/null"
    real_open = os.open
    captured: list[int] = []

    def capture_open(file: str, flags: int, mode: int = 0o777) -> int:
        fd = real_open(file, flags, mode)
        if file == device:
            captured.append(fd)
        return fd

    monkeypatch.setattr(os, "open", capture_open)
    log = AuditLogger(device)
    assert log.degraded
    assert captured
    for fd in captured:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_append_continues_when_descriptor_chmod_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    path.chmod(0o640)

    def refuse_chmod(fd: int, mode: int) -> None:
        raise PermissionError("synthetic append-only chmod refusal")

    monkeypatch.setattr(os, "fchmod", refuse_chmod)
    log = AuditLogger(str(path))
    log.record(tool="test", args={}, output="synthetic", exit_code=0, tier=0)
    assert not log.degraded
    assert json.loads(path.read_text())["tool"] == "test"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


@pytest.mark.parametrize("suffix", [".jsonl", ".gz"])
def test_tail_of_fifo_is_bounded(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / ("audit" + suffix)
    os.mkfifo(path, 0o640)
    path.chmod(0o640)
    code = """
import json,sys
from relay_shell.audit import AuditLogger
log=AuditLogger.__new__(AuditLogger);log.path=sys.argv[1]
print(json.dumps({'tail':log.tail(10)}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)],
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    assert json.loads(result.stdout)["tail"] == ""
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_verifier_rejects_path_replacement_with_fifo(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    code = """
import json,os,sys
from pathlib import Path
from relay_shell.audit import verify_chain
target=Path(sys.argv[1]);real_is_file=Path.is_file
def replace_after_stat(self):
    result=real_is_file(self)
    if self==target and result:
        self.unlink();os.mkfifo(self,0o640)
    return result
Path.is_file=replace_after_stat
r=verify_chain(str(target))
print(json.dumps({'ok':r.ok,'reason':r.reason}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)],
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    assert json.loads(result.stdout)["ok"] is False
    assert "regular file" in json.loads(result.stdout)["reason"]


def test_invalid_path_degrades_without_raising() -> None:
    log = AuditLogger("bad\x00audit")
    assert log.degraded
    log.record(tool="test", args={}, output="synthetic", exit_code=0, tier=0)


def test_unavailable_home_degrades_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable_home(self: Path) -> Path:
        raise RuntimeError("synthetic unavailable home")

    monkeypatch.setattr(Path, "expanduser", unavailable_home)
    log = AuditLogger("~/audit.jsonl")
    assert log.degraded
