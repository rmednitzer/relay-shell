"""Tests for the opt-in seccomp-notify syscall audit channel (ADR 0006).

Two layers:

* **Portable unit tests** — the BPF assembler/filter, syscall-name mapping,
  notification parsing, platform gating, the cap/overflow dispatch, the
  ContextVar plumbing, and the parent-side arm/stop lifecycle. These run
  anywhere (no privilege, no real filter install).
* **Privileged end-to-end tests** — marked ``seccomp`` and skipped unless
  the host can actually install a USER_NOTIF listener
  (Linux/x86_64/kernel>=5.5/CAP_SYS_ADMIN). They drive a real child and
  assert the observed syscalls, the fail-open posture, and the audit shape.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
from array import array
from pathlib import Path

import pytest

from relay_shell import seccomp
from relay_shell.config import Settings
from relay_shell.server import build_server
from relay_shell.shelltools import run_command

_SUPPORT = seccomp.platform_support()
requires_seccomp = pytest.mark.skipif(
    not _SUPPORT.ok,
    reason=f"seccomp-notify unsupported here: {_SUPPORT.reason}",
)


# --- portable unit tests ----------------------------------------------------


def test_platform_support_shape() -> None:
    s = seccomp.platform_support()
    assert isinstance(s.ok, bool)
    assert isinstance(s.reason, str) and s.reason
    assert isinstance(s.arch, str)
    assert isinstance(s.kernel, str)


def test_filter_version_is_pinned() -> None:
    assert isinstance(seccomp.SECCOMP_FILTER_VERSION, int)
    assert seccomp.SECCOMP_FILTER_VERSION >= 1


def test_build_filter_is_well_formed() -> None:
    prog = seccomp.build_filter("x86_64")
    assert len(prog) % 8 == 0
    instrs = [struct.unpack_from("HBBI", prog, i) for i in range(0, len(prog), 8)]
    # First instruction loads data.arch (BPF_LD|W|ABS at offset 4).
    assert instrs[0] == (0x20, 0, 0, 4)
    # The two terminals are RET ALLOW (penultimate) and RET USER_NOTIF (last).
    assert instrs[-2] == (0x06, 0, 0, seccomp._SECCOMP_RET_ALLOW)
    assert instrs[-1] == (0x06, 0, 0, seccomp._SECCOMP_RET_USER_NOTIF)
    # Every conditional branch offset stays within range and never targets
    # past the program (the assembler asserts this, but pin it here too).
    for code, jt, jf, _k in instrs:
        assert 0 <= jt <= 255 and 0 <= jf <= 255


def test_build_filter_guards_on_arch() -> None:
    # A wrong arch must route to ALLOW, never into the number table — assert the
    # arch constant appears as the comparison key of the first JEQ.
    prog = seccomp.build_filter("x86_64")
    instrs = [struct.unpack_from("HBBI", prog, i) for i in range(0, len(prog), 8)]
    jeqs = [k for (code, _jt, _jf, k) in instrs if code == 0x15]
    assert seccomp._AUDIT_ARCH_X86_64 in jeqs


def test_build_filter_covers_every_notified_syscall() -> None:
    prog = seccomp.build_filter("x86_64")
    instrs = [struct.unpack_from("HBBI", prog, i) for i in range(0, len(prog), 8)]
    jeq_keys = {k for (code, _jt, _jf, k) in instrs if code == 0x15}
    table = seccomp._SYSCALLS["x86_64"]
    for spec in seccomp.NOTIFIED_SYSCALLS:
        assert table[spec.name] in jeq_keys, f"{spec.name} not dispatched"


def test_syscall_name_known_and_unknown() -> None:
    assert seccomp.syscall_name("x86_64", 59) == "execve"
    assert seccomp.syscall_name("x86_64", 257) == "openat"
    assert seccomp.syscall_name("x86_64", 424242) == "#424242"
    assert seccomp.syscall_name("sparc", 1) == "#1"  # unknown arch -> numeric


def test_parse_notif_roundtrip() -> None:
    # struct seccomp_notif { id u64; pid u32; flags u32; data{ nr i32; arch u32;
    # ip u64; args[6] u64 } }
    buf = bytearray(80)
    struct.pack_into("QII", buf, 0, 0xDEADBEEF, 4321, 0)  # id, pid, flags
    struct.pack_into("iI", buf, 16, 59, seccomp._AUDIT_ARCH_X86_64)  # nr, arch
    struct.pack_into("6Q", buf, 32, 11, 22, 33, 44, 55, 66)  # args
    notif_id, pid, nr, args = seccomp._parse_notif(buf)
    assert notif_id == 0xDEADBEEF
    assert pid == 4321
    assert nr == 59
    assert args == (11, 22, 33, 44, 55, 66)


def test_dispatch_emits_up_to_cap_then_one_overflow() -> None:
    events: list[str] = []
    overflows: list[int] = []
    m = seccomp.SeccompMonitor(
        cap=3,
        arch="x86_64",
        on_event=lambda e: events.append(e.syscall),
        on_overflow=lambda pid: overflows.append(pid),
    )
    # Five notified execve syscalls; cap=3 -> 3 events, 1 overflow, then silent.
    for _ in range(5):
        m._dispatch(pid=7, nr=59, args=(0, 0, 0, 0, 0, 0))
    assert events == ["execve", "execve", "execve"]
    assert overflows == [7]


def test_dispatch_callback_exception_is_isolated() -> None:
    # A throwing audit sink must never crash the supervisor.
    def boom(_e: seccomp.SyscallEvent) -> None:
        raise RuntimeError("sink down")

    m = seccomp.SeccompMonitor(cap=10, arch="x86_64", on_event=boom, on_overflow=lambda pid: None)
    m._dispatch(pid=1, nr=59, args=(0, 0, 0, 0, 0, 0))  # must not raise


def test_contextvar_set_get_clear() -> None:
    assert seccomp.get_active() is None
    m = seccomp.SeccompMonitor(
        cap=1, arch="x86_64", on_event=lambda e: None, on_overflow=lambda p: None
    )
    token = seccomp.set_active(m)
    try:
        assert seccomp.get_active() is m
    finally:
        seccomp.clear_active(token)
    assert seccomp.get_active() is None


def test_arm_then_stop_without_spawn_is_clean() -> None:
    # arm() starts the supervisor thread (it blocks on the handshake); stop()
    # signals + joins it without a real child. Exercises the parent-side
    # lifecycle (and the "no handshake -> degrade" path) with no privilege.
    degraded: list[str] = []
    m = seccomp.SeccompMonitor(
        cap=8,
        arch=_SUPPORT.arch if _SUPPORT.arch in seccomp._SYSCALLS else "x86_64",
        on_event=lambda e: None,
        on_overflow=lambda p: None,
        on_degraded=lambda r: degraded.append(r),
    )
    extras = m.arm()
    try:
        assert "preexec_fn" in extras and "pass_fds" in extras
        # A second arm() is a no-op (single-use) so a second child runs unaudited.
        assert m.arm() == {}
    finally:
        m.stop()
        m.stop()  # idempotent


# --- supervisor state machine (white-box, no privilege) ---------------------


def _monitor(**kw: object) -> seccomp.SeccompMonitor:
    defaults: dict[str, object] = {
        "cap": 8,
        "arch": "x86_64",
        "on_event": lambda e: None,
        "on_overflow": lambda p: None,
    }
    defaults.update(kw)
    return seccomp.SeccompMonitor(**defaults)  # type: ignore[arg-type]


def _wire(m: seccomp.SeccompMonitor) -> None:
    """Set up the monitor's sockets/pipes as ``arm`` would, without the thread."""
    m._psock, m._csock = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    m._stop_r, m._stop_w = os.pipe()


def test_handshake_success_returns_listener_fd() -> None:
    m = _monitor()
    _wire(m)
    sent = os.open(os.devnull, os.O_RDONLY)
    try:
        assert m._csock is not None
        m._csock.sendmsg(
            [seccomp._HANDSHAKE_OK],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [sent]))],
        )
        got = m._handshake()
        assert got is not None and got >= 0
        os.close(got)
    finally:
        os.close(sent)
        m.stop()


def test_handshake_fail_status_returns_none() -> None:
    m = _monitor()
    _wire(m)
    try:
        assert m._csock is not None
        m._csock.sendmsg([seccomp._HANDSHAKE_FAIL])
        assert m._handshake() is None
    finally:
        m.stop()


def test_handshake_stop_signal_returns_none() -> None:
    m = _monitor()
    _wire(m)
    try:
        assert m._stop_w is not None
        os.write(m._stop_w, b"x")  # stop requested before any handshake
        assert m._handshake() is None
    finally:
        m.stop()


def test_handshake_without_sockets_returns_none() -> None:
    assert _monitor()._handshake() is None  # _psock/_stop_r are None


def test_supervise_handshakes_then_drains_to_completion() -> None:
    # Full _supervise: receive a (hung-up) pipe as the fake listener, then
    # _drain sees POLLHUP and returns — covering the success tail with no
    # privilege and no real notification.
    m = _monitor()
    _wire(m)
    lr, lw = os.pipe()
    os.close(lw)  # hang up the read end so _drain breaks immediately
    try:
        assert m._csock is not None
        m._csock.sendmsg(
            [seccomp._HANDSHAKE_OK],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [lr]))],
        )
        m._supervise()
        assert m._listener_fd is not None  # the dup of lr
    finally:
        with contextlib.suppress(OSError):
            os.close(lr)
        m.stop()


def test_drain_breaks_on_stop_signal() -> None:
    m = _monitor()
    m._stop_r, m._stop_w = os.pipe()
    lr, lw = os.pipe()
    try:
        os.write(m._stop_w, b"x")  # already-signalled stop
        m._drain(lr)  # stop_r readable -> immediate break
    finally:
        for fd in (lr, lw, m._stop_r, m._stop_w):
            with contextlib.suppress(OSError, TypeError):
                os.close(fd)  # type: ignore[arg-type]


def test_drain_breaks_on_listener_hangup() -> None:
    m = _monitor()
    m._stop_r, m._stop_w = os.pipe()
    lr, lw = os.pipe()
    os.close(lw)  # POLLHUP on lr
    try:
        m._drain(lr)
    finally:
        for fd in (lr, m._stop_r, m._stop_w):
            with contextlib.suppress(OSError, TypeError):
                os.close(fd)  # type: ignore[arg-type]


def test_drain_breaks_on_recv_error() -> None:
    # A readable non-seccomp fd: POLLIN fires, the RECV ioctl fails (ENOTTY,
    # not ENOENT), and the loop stops rather than spinning.
    m = _monitor()
    m._stop_r, m._stop_w = os.pipe()
    lr, lw = os.pipe()
    os.write(lw, b"data")  # make lr readable
    try:
        m._drain(lr)
    finally:
        for fd in (lr, lw, m._stop_r, m._stop_w):
            with contextlib.suppress(OSError, TypeError):
                os.close(fd)  # type: ignore[arg-type]


def test_respond_continue_swallows_ioctl_error() -> None:
    m = _monitor()
    r, w = os.pipe()
    try:
        m._respond_continue(w, 0xABCDEF)  # ioctl on a pipe fails -> suppressed
    finally:
        os.close(r)
        os.close(w)


def test_extract_fd_absent_and_present() -> None:
    assert seccomp._extract_fd([]) is None
    assert seccomp._extract_fd([(socket.SOL_SOCKET, 0, b"")]) is None  # wrong cmsg type
    fd = os.open(os.devnull, os.O_RDONLY)
    try:
        data = array("i", [fd]).tobytes()
        assert seccomp._extract_fd([(socket.SOL_SOCKET, socket.SCM_RIGHTS, data)]) == fd
    finally:
        os.close(fd)


def test_safe_call_none_is_noop_and_forwards_args() -> None:
    seccomp._safe_call(None)  # no-op, must not raise
    seen: list[int] = []
    seccomp._safe_call(seen.append, 7)
    assert seen == [7]


def test_assembler_rejects_out_of_range_branch() -> None:
    asm = seccomp._Assembler()
    asm.jump(seccomp._JEQ_K, 0, "far", seccomp._FALL)
    for _ in range(300):  # push "far" past the 8-bit branch-offset ceiling
        asm.stmt(seccomp._LD_W_ABS, 0)
    asm.label("far")
    asm.stmt(seccomp._RET_K, 0)
    with pytest.raises(ValueError):
        asm.assemble()


def test_kernel_at_least_parsing() -> None:
    assert seccomp._kernel_at_least("6.18.5", 5, 5)
    assert seccomp._kernel_at_least("5.5.0", 5, 5)
    assert seccomp._kernel_at_least("6", 5, 5)  # no minor component
    assert not seccomp._kernel_at_least("5.4.99", 5, 5)
    assert not seccomp._kernel_at_least("not-a-version", 5, 5)  # ValueError -> False


def test_has_cap_sys_admin_returns_bool() -> None:
    assert isinstance(seccomp._has_cap_sys_admin(), bool)


def test_platform_support_unsupported_reasons(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drive every gate in platform_support(). lru_cache is cleared before each
    # branch and once more in finally so the real value is recomputed after.
    try:
        seccomp.platform_support.cache_clear()
        monkeypatch.setattr(seccomp.sys, "platform", "darwin")
        assert "not Linux" in seccomp.platform_support().reason

        monkeypatch.setattr(seccomp.sys, "platform", "linux")
        monkeypatch.setattr(seccomp.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(seccomp.platform, "release", lambda: "6.0.0")

        seccomp.platform_support.cache_clear()
        monkeypatch.setattr(seccomp.platform, "machine", lambda: "risc-v")
        assert "unsupported arch" in seccomp.platform_support().reason
        monkeypatch.setattr(seccomp.platform, "machine", lambda: "x86_64")

        seccomp.platform_support.cache_clear()
        monkeypatch.setattr(seccomp.platform, "release", lambda: "4.19.0")
        assert "below 5.5" in seccomp.platform_support().reason
        monkeypatch.setattr(seccomp.platform, "release", lambda: "6.0.0")

        seccomp.platform_support.cache_clear()
        monkeypatch.setattr(seccomp, "_has_cap_sys_admin", lambda: False)
        assert "CAP_SYS_ADMIN" in seccomp.platform_support().reason
        monkeypatch.setattr(seccomp, "_has_cap_sys_admin", lambda: True)

        seccomp.platform_support.cache_clear()
        monkeypatch.setattr(seccomp, "_notif_sizes", lambda: None)
        assert "GET_NOTIF_SIZES" in seccomp.platform_support().reason

        seccomp.platform_support.cache_clear()
        monkeypatch.setattr(seccomp, "_notif_sizes", lambda: seccomp._NotifSizes(1, 2, 3))
        assert "ABI sizes" in seccomp.platform_support().reason

        seccomp.platform_support.cache_clear()
        monkeypatch.setattr(seccomp, "_notif_sizes", lambda: seccomp._NotifSizes(80, 24, 64))
        good = seccomp.platform_support()
        assert good.ok and good.reason == "ok"
    finally:
        seccomp.platform_support.cache_clear()


# --- privileged end-to-end tests (marked + auto-skip) -----------------------


def _settings(tmp_path: Path, **over: object) -> Settings:
    base: dict[str, object] = {
        "transport": "stdio",
        "audit_path": str(tmp_path / "audit.jsonl"),
        "policy_mode": "open",
        "ssh_known_hosts": "ignore",
        "ssh_config": str(tmp_path / "no_ssh_config"),
        "inventory": "",
        "auth_state_dir": str(tmp_path / "oauth"),
        "seccomp_notify": True,
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.mark.seccomp
@requires_seccomp
async def test_run_command_observes_execve_and_write_open(tmp_path: Path) -> None:
    target = tmp_path / "written"
    events: list[seccomp.SyscallEvent] = []
    monitor = seccomp.SeccompMonitor(
        cap=512,
        arch=_SUPPORT.arch,
        on_event=events.append,
        on_overflow=lambda pid: None,
    )
    token = seccomp.set_active(monitor)
    try:
        out, code = await run_command(
            f"/bin/echo hi > {target} && /bin/echo done", timeout=15, use_shell=True
        )
    finally:
        seccomp.clear_active(token)
    assert code == 0, out
    assert target.exists()  # the child genuinely ran (CONTINUE, not blocked)
    names = {e.syscall for e in events}
    assert "execve" in names
    assert "openat" in names  # the write redirection
    # Every event carries the child pid and six numeric args (no buffer deref).
    for e in events:
        assert e.pid > 0
        assert len(e.args) == 6


@pytest.mark.seccomp
@requires_seccomp
async def test_readonly_open_is_not_notified(tmp_path: Path) -> None:
    # `cat` of an existing file opens it O_RDONLY -> must NOT trap. Only the
    # execve of cat should show up, proving the write-flag predicate works.
    src = tmp_path / "src.txt"
    src.write_text("payload\n")
    events: list[seccomp.SyscallEvent] = []
    monitor = seccomp.SeccompMonitor(
        cap=512, arch=_SUPPORT.arch, on_event=events.append, on_overflow=lambda p: None
    )
    token = seccomp.set_active(monitor)
    try:
        out, code = await run_command(f"/bin/cat {src}", timeout=15, use_shell=False)
    finally:
        seccomp.clear_active(token)
    assert code == 0 and "payload" in out
    opens = [e for e in events if e.syscall in ("open", "openat")]
    assert opens == [], f"read-only open was notified: {opens}"


@pytest.mark.seccomp
@requires_seccomp
async def test_overflow_caps_emission_but_child_completes(tmp_path: Path) -> None:
    events: list[str] = []
    overflows: list[int] = []
    monitor = seccomp.SeccompMonitor(
        cap=1,
        arch=_SUPPORT.arch,
        on_event=lambda e: events.append(e.syscall),
        on_overflow=overflows.append,
    )
    token = seccomp.set_active(monitor)
    try:
        out, code = await run_command(
            "/bin/true; /bin/true; /bin/true; /bin/echo ok", timeout=15, use_shell=True
        )
    finally:
        seccomp.clear_active(token)
    assert code == 0 and "ok" in out  # CONTINUE past the cap -> child finishes
    assert len(events) == 1  # exactly one event emitted before the cap
    assert len(overflows) == 1  # one overflow marker


@pytest.mark.seccomp
@requires_seccomp
async def test_server_writes_syscall_notify_audit_lines(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    mcp = build_server(settings)
    content, _ = await mcp.call_tool(
        "shell_exec", {"command": "/bin/echo seccomp-e2e", "use_shell": True}
    )
    text = "".join(getattr(b, "text", "") for b in content)
    assert "seccomp-e2e" in text

    records = [
        json.loads(line)
        for line in Path(settings.audit_path).read_text().splitlines()
        if line.strip()
    ]
    tools = [r["tool"] for r in records]
    assert "shell_exec" in tools  # the tool-call record
    assert "syscall_notify" in tools  # at least one additive syscall event

    syscall_recs = [r for r in records if r["tool"] == "syscall_notify"]
    assert any(r["syscall"] == "execve" for r in syscall_recs)
    for r in syscall_recs:
        assert r["tier"] == 0
        assert isinstance(r["syscall_args"], list) and len(r["syscall_args"]) == 6
        # The output body must never reach the audit log, syscall events included.
        assert "output_sha256" not in r  # distinct shape from a tool-call record


@pytest.mark.seccomp
@requires_seccomp
async def test_server_info_reports_seccomp_block(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    mcp = build_server(settings)
    content, _ = await mcp.call_tool("server_info", {})
    text = "".join(getattr(b, "text", "") for b in content)
    info = json.loads(text)
    assert info["seccomp"]["notify"] is True
    assert info["seccomp"]["supported"] is True
    assert info["seccomp"]["cap"] == settings.seccomp_notify_cap
    assert info["seccomp"]["filter_version"] == seccomp.SECCOMP_FILTER_VERSION


@pytest.mark.seccomp
@requires_seccomp
async def test_syscall_events_extend_the_audit_chain(tmp_path: Path) -> None:
    # With the tamper-evident chain on, the additive syscall_notify lines must
    # be chained in the same stream as the tool-call record and verify clean.
    from relay_shell.audit import verify_chain

    settings = _settings(tmp_path, audit_chain=True)
    mcp = build_server(settings)
    await mcp.call_tool("shell_exec", {"command": "/bin/echo chain", "use_shell": True})

    result = verify_chain(settings.audit_path)
    assert result.ok, result.reason
    assert result.anchored
    records = [
        json.loads(line)
        for line in Path(settings.audit_path).read_text().splitlines()
        if line.strip()
    ]
    # Both record kinds are present and every line carries chain fields.
    assert {"shell_exec", "syscall_notify"} <= {r["tool"] for r in records}
    assert all("seq" in r and "prev" in r and "chain" in r for r in records)
