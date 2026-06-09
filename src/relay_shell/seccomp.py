"""Opt-in, audit-only syscall notification channel (ADR 0006, B-021).

This module adds a *forensic* view of what a locally-spawned child does
*after* ``exec`` returns, without re-introducing a sandbox. It installs a
``seccomp-bpf`` filter on the child that traps a small, high-signal set of
syscalls in **user-notification** mode (``SECCOMP_RET_USER_NOTIF``); a
supervisor thread in the parent reads each notification, emits one audit
event, and **always** answers ``SECCOMP_USER_NOTIF_FLAG_CONTINUE`` so the
syscall proceeds exactly as it would have. Nothing is blocked, no argument
is rewritten, no child is killed.

Posture invariant (ADR 0002 preserved verbatim): a seccomp filter can be
installed two ways — with ``CAP_SYS_ADMIN`` or by first latching
``no_new_privs``. We use **only** the ``CAP_SYS_ADMIN`` path. Latching
``no_new_privs`` would silently disable set-uid escalation in the child
(``sudo`` would stop working), a real capability regression this project
forbids. So the channel activates **only** when the server process holds
``CAP_SYS_ADMIN`` (e.g. runs as root, a supported privileged posture);
otherwise it cleanly no-ops and the spawn path is byte-identical to today.

Scope: the one-shot local executor (``shell_exec`` / ``shell_script``
/ ``ssh_keyscan`` via :mod:`relay_shell.shelltools`) and long-lived local
PTY sessions (``shell_spawn`` via :mod:`relay_shell.sessions`, where the
monitor's lifetime follows the session — runbook B-026). SSH sessions have
no local child (``asyncssh`` runs in-process), so there is nothing local
to observe on that path. Linux + ``x86_64`` only; every other platform,
arch, or a kernel below 5.5 makes the feature report ``supported=False``
and no-op.

Everything here is fail-open for the child: if the filter cannot be
installed, the handshake fails, or the supervisor dies, the child runs
unfiltered and the audit pipeline records the gap as degraded — it never
breaks a tool call.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import logging
import os
import platform
import select
import socket
import struct
import sys
import threading
from array import array
from collections.abc import Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

__all__ = [
    "NOTIFIED_SYSCALLS",
    "PRCTL_NOTIFIED_OPTIONS",
    "SECCOMP_FILTER_VERSION",
    "PlatformSupport",
    "SeccompMonitor",
    "SyscallEvent",
    "build_filter",
    "clear_active",
    "get_active",
    "platform_support",
    "set_active",
    "syscall_name",
]

_log = logging.getLogger("relay_shell.seccomp")

# Bump whenever the installed filter or the notified-syscall set changes, so
# the audit trail and server_info can pin which policy produced an event.
# Mirrors patterns.PATTERNS_VERSION.
# 2: prctl joined the notified set, gated on the privilege-relevant
#    PRCTL_NOTIFIED_OPTIONS via the eq-any predicate (runbook B-024).
SECCOMP_FILTER_VERSION: Final = 2

# --- kernel ABI constants (validated against a live host; see ADR 0006) -----

_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_GET_NOTIF_SIZES = 3
# SECCOMP_FILTER_FLAG_NEW_LISTENER is (1 << 3); (1 << 4) is TSYNC_ESRCH — a
# classic off-by-one that silently installs a plain (listener-less) filter.
_SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
_SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_USER_NOTIF = 0x7FC00000

# AUDIT_ARCH_* — the filter guards on data.arch so a 32-bit/compat syscall on
# a 64-bit host is not misread against the 64-bit number table (it falls
# through to ALLOW; compat syscalls are simply not notified — this is an
# audit aid, not a sandbox).
_AUDIT_ARCH_X86_64 = 0xC000003E

# Per-arch syscall numbers. Only arches we can actually validate ship here;
# an unknown arch makes platform_support() report unsupported and the channel
# no-ops, so a wrong/guessed number can never notify the wrong syscall.
_SYSCALLS: Final[dict[str, dict[str, int]]] = {
    "x86_64": {
        "execve": 59,
        "execveat": 322,
        "ptrace": 101,
        "mount": 165,
        "umount2": 166,
        "unshare": 272,
        "setns": 308,
        "chroot": 161,
        "pivot_root": 155,
        "setuid": 105,
        "setgid": 106,
        "setreuid": 113,
        "setregid": 114,
        "setresuid": 117,
        "setresgid": 119,
        "openat": 257,
        "open": 2,
        "prctl": 157,
    },
}
_AUDIT_ARCH: Final[dict[str, int]] = {"x86_64": _AUDIT_ARCH_X86_64}
# syscall(2) number for seccomp(2) itself, per arch.
_NR_SECCOMP: Final[dict[str, int]] = {"x86_64": 317}

# Open flags that mark a *write/create* intent. O_WRONLY(1) | O_RDWR(2) |
# O_CREAT(0o100). A read-only open (O_RDONLY == 0, no O_CREAT) ANDs to 0 and
# is not notified — that is what keeps the volume bounded (a plain `ls` or a
# dynamic linker opening libraries does not trap).
_O_WRITE_MASK = 0o100 | 0o1 | 0o2  # 0x43

# prctl(2) `option` values that change the privilege / capability /
# traceability posture of the calling process (validated against a live
# host's <linux/prctl.h>; see ADR 0006 and runbook B-024). The eq-any
# predicate notifies prctl ONLY for these, which is what keeps the volume
# bounded: high-frequency benign options (PR_SET_NAME from every thread
# naming itself, glibc's PR_SET_VMA tagging, ...) never trap.
_PR_SET_DUMPABLE = 4  # anti-forensics: hides the child from core dumps/ptrace
_PR_SET_KEEPCAPS = 8  # keep permitted caps across a setuid transition
_PR_SET_SECCOMP = 22  # child installing its own (nested) filter
_PR_CAPBSET_DROP = 24  # drop a capability from the bounding set
_PR_SET_SECUREBITS = 28  # rewire the capability inheritance rules
_PR_SET_NO_NEW_PRIVS = 38  # never *set* by this module (see docstring); audited
_PR_CAP_AMBIENT = 47  # raise/lower ambient capabilities

PRCTL_NOTIFIED_OPTIONS: Final[tuple[int, ...]] = (
    _PR_SET_DUMPABLE,
    _PR_SET_KEEPCAPS,
    _PR_SET_SECCOMP,
    _PR_CAPBSET_DROP,
    _PR_SET_SECUREBITS,
    _PR_SET_NO_NEW_PRIVS,
    _PR_CAP_AMBIENT,
)


@dataclass(frozen=True)
class _Notify:
    """One notified syscall: unconditional, or gated on one argument predicate.

    ``flag_arg``/``flag_mask`` notify when the argument has any masked bit
    set (the write-open detection). ``eq_arg``/``eq_values`` notify when the
    argument equals any listed value (the prctl option filter). At most one
    predicate kind per entry; both ``None`` means unconditional.
    """

    name: str
    flag_arg: int | None = None  # None => no flag predicate; else seccomp_data arg index
    flag_mask: int = 0
    eq_arg: int | None = None  # None => no eq-any predicate; else seccomp_data arg index
    eq_values: tuple[int, ...] = ()


# The forensically-interesting set: process execution, privilege/identity
# changes, namespace/mount manipulation, debugger attach, *writing* file
# opens, and privilege-relevant prctl options. Each is low-volume and
# high-signal; none requires dereferencing a user buffer (we record only the
# raw scalar register arguments). 32-bit compat syscalls remain deferred
# (ADR 0006).
NOTIFIED_SYSCALLS: Final[tuple[_Notify, ...]] = (
    _Notify("execve"),
    _Notify("execveat"),
    _Notify("ptrace"),
    _Notify("mount"),
    _Notify("umount2"),
    _Notify("unshare"),
    _Notify("setns"),
    _Notify("chroot"),
    _Notify("pivot_root"),
    _Notify("setuid"),
    _Notify("setgid"),
    _Notify("setreuid"),
    _Notify("setregid"),
    _Notify("setresuid"),
    _Notify("setresgid"),
    _Notify("openat", flag_arg=2, flag_mask=_O_WRITE_MASK),
    _Notify("open", flag_arg=1, flag_mask=_O_WRITE_MASK),
    _Notify("prctl", eq_arg=0, eq_values=PRCTL_NOTIFIED_OPTIONS),
)

_CAP_SYS_ADMIN = 21  # capability bit number


# --- libc handle ------------------------------------------------------------
#
# A single process-wide handle with explicit argtypes. The variadic
# ``syscall(2)`` and ``ioctl(2)`` wrappers MUST have argtypes pinned or
# ctypes mis-marshals the flag/request word (the bug that silently drops
# NEW_LISTENER and yields ENOTTY on the notify ioctls).
try:
    _lib = ctypes.CDLL("libc.so.6", use_errno=True)
    _lib.syscall.restype = ctypes.c_long
    _lib.syscall.argtypes = [ctypes.c_long, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
    _lib.ioctl.restype = ctypes.c_int
    _lib.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
    _libc: ctypes.CDLL | None = _lib
except OSError:  # pragma: no cover - only on exotic libc-less hosts
    _libc = None


def _ioc(direction: int, typ: int, nr: int, size: int) -> int:
    """Linux ``_IOC`` request-number encoder (asm-generic layout)."""
    return (direction << 30) | (size << 16) | (typ << 8) | nr


# --- struct geometry --------------------------------------------------------
#
# struct seccomp_notif { __u64 id; __u32 pid; __u32 flags; struct seccomp_data data; }
# struct seccomp_data  { int nr; __u32 arch; __u64 ip; __u64 args[6]; }
# struct seccomp_notif_resp { __u64 id; __s64 val; __s32 error; __u32 flags; }
_NOTIF_DATA_OFFSET = 16  # seccomp_data starts here within seccomp_notif
_DATA_ARGS_OFFSET = 16  # args[] start within seccomp_data
_EXPECTED_NOTIF_SIZE = 80
_EXPECTED_RESP_SIZE = 24
_EXPECTED_DATA_SIZE = 64
_RESP_PACK = "QqiI"  # id(u64), val(s64), error(s32), flags(u32)


@dataclass(frozen=True)
class _NotifSizes:
    notif: int
    resp: int
    data: int


@dataclass(frozen=True)
class PlatformSupport:
    """Whether the seccomp-notify channel can run on this host."""

    ok: bool
    reason: str
    arch: str
    kernel: str


@dataclass(frozen=True)
class SyscallEvent:
    """One observed (and allowed-to-continue) syscall. No buffers dereferenced."""

    pid: int
    syscall: str
    nr: int
    args: tuple[int, int, int, int, int, int]


def syscall_name(arch: str, nr: int) -> str:
    """Map a syscall number back to its name for the audit event, or ``"#<nr>"``."""
    table = _SYSCALLS.get(arch, {})
    for name, num in table.items():
        if num == nr:
            return name
    return f"#{nr}"


# --- BPF filter assembly ----------------------------------------------------

_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_JSET = 0x40
_BPF_JA = 0x00
_BPF_K = 0x00
_BPF_RET = 0x06
_LD_W_ABS = _BPF_LD | _BPF_W | _BPF_ABS  # 0x20
_JEQ_K = _BPF_JMP | _BPF_JEQ | _BPF_K  # 0x15
_JSET_K = _BPF_JMP | _BPF_JSET | _BPF_K  # 0x45
_JA = _BPF_JMP | _BPF_JA | _BPF_K  # 0x05
_RET_K = _BPF_RET | _BPF_K  # 0x06

_FALL = "@fall"  # sentinel label meaning "the next instruction" (offset 0)


class _Assembler:
    """A two-pass label assembler for the tiny classic-BPF filter program.

    Keeping the program symbolic (jump *targets* are labels, resolved to
    byte offsets at the end) makes the filter readable and unit-testable
    instead of a wall of hand-counted offsets.
    """

    def __init__(self) -> None:
        self._ins: list[tuple[str, int, int, str, str]] = []
        self._labels: dict[str, int] = {}

    def label(self, name: str) -> None:
        self._labels[name] = len(self._ins)

    def stmt(self, code: int, k: int) -> None:
        self._ins.append(("stmt", code, k, "", ""))

    def jump(self, code: int, k: int, jt: str, jf: str) -> None:
        self._ins.append(("jump", code, k, jt, jf))

    def ja(self, target: str) -> None:
        self._ins.append(("ja", _JA, 0, target, ""))

    def assemble(self) -> bytes:
        out = bytearray()
        for idx, (kind, code, k, jt, jf) in enumerate(self._ins):
            if kind == "stmt":
                out += struct.pack("HBBI", code, 0, 0, k & 0xFFFFFFFF)
            elif kind == "ja":
                off = self._labels[jt] - (idx + 1)
                if not 0 <= off <= 0xFFFFFFFF:  # pragma: no cover - forward JA is always small
                    raise ValueError(f"JA target out of range at {idx}")
                out += struct.pack("HBBI", code, 0, 0, off)
            else:  # conditional jump
                jt_off = 0 if jt == _FALL else self._labels[jt] - (idx + 1)
                jf_off = 0 if jf == _FALL else self._labels[jf] - (idx + 1)
                if not (0 <= jt_off <= 255 and 0 <= jf_off <= 255):
                    raise ValueError(f"branch offset out of range at instruction {idx}")
                out += struct.pack("HBBI", code, jt_off, jf_off, k & 0xFFFFFFFF)
        return bytes(out)


def build_filter(arch: str) -> bytes:
    """Build the classic-BPF program for ``arch`` as packed ``sock_filter[]``.

    Shape: guard on ``data.arch`` (anything else -> ALLOW), then dispatch on
    ``data.nr``. Unconditional syscalls branch straight to NOTIFY; ``open`` /
    ``openat`` first load their flags argument and NOTIFY only when a
    write/create bit is set; ``prctl`` loads its ``option`` argument and
    NOTIFYs only when it equals one of :data:`PRCTL_NOTIFIED_OPTIONS`.
    Anything unmatched falls to ALLOW.
    """
    table = _SYSCALLS[arch]
    arch_const = _AUDIT_ARCH[arch]
    asm = _Assembler()

    asm.stmt(_LD_W_ABS, 4)  # A = data.arch
    asm.jump(_JEQ_K, arch_const, _FALL, "allow")  # wrong arch -> ALLOW
    asm.stmt(_LD_W_ABS, 0)  # A = data.nr

    conditional: list[_Notify] = []
    for spec in NOTIFIED_SYSCALLS:
        if spec.name not in table:  # pragma: no cover - x86_64 table has every notified syscall
            continue
        if spec.eq_arg is not None and not spec.eq_values:
            # An empty eq-any set would assemble to a bare argument load that
            # falls through into the NEXT conditional block — silently testing
            # the wrong syscall's predicate. Refuse to build instead.
            raise ValueError(f"{spec.name}: eq_arg set but eq_values is empty")
        if spec.flag_arg is None and spec.eq_arg is None:
            asm.jump(_JEQ_K, table[spec.name], "notify", _FALL)
        else:
            conditional.append(spec)
    # nr matched none of the unconditional set; route the conditional ones,
    # then fall to ALLOW.
    for i, spec in enumerate(conditional):
        asm.jump(_JEQ_K, table[spec.name], f"ck{i}", _FALL)
    asm.ja("allow")

    for i, spec in enumerate(conditional):
        asm.label(f"ck{i}")
        # args[] are 64-bit; the low 32 bits carry the open flags / the prctl
        # option (both are ints well under 2^32). Little-endian hosts keep
        # the low word at the slot's start.
        if spec.flag_arg is not None:
            asm.stmt(_LD_W_ABS, _DATA_ARGS_OFFSET + spec.flag_arg * 8)
            asm.jump(_JSET_K, spec.flag_mask, "notify", "allow")
        else:
            # eq-any (B-024): any listed value -> NOTIFY, else ALLOW.
            asm.stmt(_LD_W_ABS, _DATA_ARGS_OFFSET + (spec.eq_arg or 0) * 8)
            for j, val in enumerate(spec.eq_values):
                jf = "allow" if j == len(spec.eq_values) - 1 else _FALL
                asm.jump(_JEQ_K, val, "notify", jf)

    asm.label("allow")
    asm.stmt(_RET_K, _SECCOMP_RET_ALLOW)
    asm.label("notify")
    asm.stmt(_RET_K, _SECCOMP_RET_USER_NOTIF)
    return asm.assemble()


# --- platform capability check ----------------------------------------------


def _kernel_at_least(release: str, major: int, minor: int) -> bool:
    parts = release.split("-", 1)[0].split(".")
    try:
        kmaj = int(parts[0])
        kmin = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return False
    return (kmaj, kmin) >= (major, minor)


def _has_cap_sys_admin() -> bool:
    """True iff the calling process holds CAP_SYS_ADMIN in its effective set.

    Parsed from ``/proc/self/status`` (``CapEff``) so it is accurate under
    file/ambient capabilities, not just a ``euid == 0`` proxy.
    """
    try:
        with Path("/proc/self/status").open(encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    mask = int(line.split()[1], 16)
                    return bool((mask >> _CAP_SYS_ADMIN) & 1)
    except (OSError, ValueError):
        return False
    return False


def _notif_sizes() -> _NotifSizes | None:
    """Query the kernel's notify struct sizes (SECCOMP_GET_NOTIF_SIZES)."""
    if _libc is None:
        return None

    class _S(ctypes.Structure):
        _fields_ = [
            ("notif", ctypes.c_uint16),
            ("resp", ctypes.c_uint16),
            ("data", ctypes.c_uint16),
        ]

    s = _S()
    rc = _libc.syscall(
        _NR_SECCOMP.get(platform.machine(), -1),
        _SECCOMP_GET_NOTIF_SIZES,
        0,
        ctypes.byref(s),
    )
    if rc != 0:
        return None
    return _NotifSizes(int(s.notif), int(s.resp), int(s.data))


@lru_cache(maxsize=1)
def platform_support() -> PlatformSupport:
    """Whether the seccomp-notify channel can run here (cached for the process).

    ``ok`` means the static prerequisites hold (Linux, a known arch, kernel
    >= 5.5, ``CAP_SYS_ADMIN``, and a notify ABI matching what this module
    encodes). A runtime that still blocks ``seccomp(2)`` (e.g. a restrictive
    container profile) degrades gracefully per-call rather than failing here.
    """
    arch = platform.machine()
    kernel = platform.release()
    if not sys.platform.startswith("linux"):
        return PlatformSupport(False, f"not Linux ({sys.platform})", arch, kernel)
    if _libc is None:
        return PlatformSupport(False, "libc unavailable", arch, kernel)
    if arch not in _SYSCALLS:
        return PlatformSupport(False, f"unsupported arch {arch!r} (x86_64 only)", arch, kernel)
    if not _kernel_at_least(kernel, 5, 5):
        return PlatformSupport(False, f"kernel {kernel} below 5.5 floor", arch, kernel)
    if not _has_cap_sys_admin():
        # The CAP_SYS_ADMIN-only install path is deliberate: see module
        # docstring. Without it we will not latch no_new_privs, so we cannot
        # install a filter — and we refuse to, rather than change posture.
        return PlatformSupport(False, "requires CAP_SYS_ADMIN", arch, kernel)
    sizes = _notif_sizes()
    if sizes is None:
        return PlatformSupport(False, "SECCOMP_GET_NOTIF_SIZES unavailable", arch, kernel)
    if (sizes.notif, sizes.resp, sizes.data) != (
        _EXPECTED_NOTIF_SIZE,
        _EXPECTED_RESP_SIZE,
        _EXPECTED_DATA_SIZE,
    ):
        return PlatformSupport(
            False,
            f"notify ABI sizes {sizes} differ from expected "
            f"({_EXPECTED_NOTIF_SIZE}/{_EXPECTED_RESP_SIZE}/{_EXPECTED_DATA_SIZE})",
            arch,
            kernel,
        )
    return PlatformSupport(True, "ok", arch, kernel)


# --- per-call monitor -------------------------------------------------------

_START_HANDSHAKE_TIMEOUT = 5.0  # seconds to wait for the child's status byte
_STOP_JOIN_TIMEOUT = 5.0  # seconds to wait for the supervisor thread to exit
_HANDSHAKE_OK = b"\x01"
_HANDSHAKE_FAIL = b"\x00"


class SeccompMonitor:
    """Installs the filter on one child and supervises its notifications.

    Single-use and fail-open: at most one child is audited per monitor; any
    failure on the seccomp path lets the child run unfiltered and reports a
    degraded gap. Construction performs no syscalls — only :meth:`popen_extras`
    (called pre-spawn) and :meth:`start` (post-spawn) touch the kernel.
    """

    def __init__(
        self,
        *,
        cap: int,
        arch: str,
        on_event: Callable[[SyscallEvent], None],
        on_overflow: Callable[[int], None],
        on_degraded: Callable[[str], None] | None = None,
    ) -> None:
        self._cap = max(1, int(cap))
        self._arch = arch
        self._on_event = on_event
        self._on_overflow = on_overflow
        self._on_degraded = on_degraded

        self._sizes = _notif_sizes() or _NotifSizes(
            _EXPECTED_NOTIF_SIZE, _EXPECTED_RESP_SIZE, _EXPECTED_DATA_SIZE
        )
        typ = ord("!")
        self._recv_cmd = _ioc(3, typ, 0, self._sizes.notif)
        self._send_cmd = _ioc(3, typ, 1, self._sizes.resp)

        # Pre-built so the post-fork child does as little as possible.
        self._prog_buf: ctypes.Array[ctypes.c_char] | None = None
        self._fprog: ctypes.Structure | None = None
        self._psock: socket.socket | None = None
        self._csock: socket.socket | None = None
        self._used = False

        # Supervisor state.
        self._listener_fd: int | None = None
        self._stop_r: int | None = None
        self._stop_w: int | None = None
        self._thread: threading.Thread | None = None
        self._stopped = False
        self._count = 0

    # -- pre-spawn ----------------------------------------------------------

    def arm(self) -> dict[str, object]:
        """Prepare the child filter, start the supervisor, return ``Popen`` kwargs.

        The supervisor thread is started **here, before the spawn**: a
        ``preexec_fn``-installed USER_NOTIF filter traps the child's own
        ``execve``, and ``Popen`` does not return until that ``execve``
        completes. Only a supervisor already draining the listener can answer
        CONTINUE and let the spawn finish — so arming must precede spawning.

        Single-use: a second call (a tool spawning more than one local child)
        returns ``{}`` so the extra child runs unaudited rather than reusing a
        spent socketpair.
        """
        if self._used or _libc is None:
            return {}
        self._used = True
        prog = build_filter(self._arch)
        self._prog_buf = (ctypes.c_char * len(prog)).from_buffer_copy(prog)

        class _Fprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

        self._fprog = _Fprog(len(prog) // 8, ctypes.cast(self._prog_buf, ctypes.c_void_p))
        self._psock, self._csock = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._stop_r, self._stop_w = os.pipe()
        self._thread = threading.Thread(
            target=self._supervise, name="relay-seccomp-notify", daemon=True
        )
        self._thread.start()
        return {"preexec_fn": self._install_in_child, "pass_fds": (self._csock.fileno(),)}

    def _install_in_child(self) -> None:  # pragma: no cover
        """Runs in the forked child, after fd cleanup, before ``exec``.

        Must NEVER raise (a raising ``preexec_fn`` aborts the spawn and would
        break the tool). On any failure it signals the parent and returns so
        ``exec`` proceeds unfiltered. Kept to bare syscalls on pre-built
        buffers to minimise the post-fork window.

        Not coverable: this executes in the forked child between fork and
        ``exec``; the child then replaces itself via ``execve`` so the
        coverage tracer's data is never written back. The ``seccomp``-marked
        end-to-end tests exercise it for real on a privileged host.
        """
        csock = self._csock
        nr_seccomp = _NR_SECCOMP.get(self._arch, -1)
        fd = -1
        with contextlib.suppress(Exception):
            assert _libc is not None and self._fprog is not None
            fd = int(
                _libc.syscall(
                    nr_seccomp,
                    _SECCOMP_SET_MODE_FILTER,
                    _SECCOMP_FILTER_FLAG_NEW_LISTENER,
                    ctypes.byref(self._fprog),
                )
            )
        if csock is None:
            return
        if fd < 0:
            with contextlib.suppress(Exception):
                csock.sendmsg([_HANDSHAKE_FAIL])
            with contextlib.suppress(Exception):
                csock.close()
            return
        with contextlib.suppress(Exception):
            csock.sendmsg(
                [_HANDSHAKE_OK],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [fd]))],
            )
        with contextlib.suppress(Exception):
            os.close(fd)
        with contextlib.suppress(Exception):
            csock.close()

    # -- supervisor (own daemon thread, started by arm) ---------------------

    def _supervise(self) -> None:
        """Handshake for the listener fd, then drain notifications.

        Phase 1 waits (interruptibly) for the child's handshake datagram;
        phase 2 answers CONTINUE for every notification and audits up to the
        per-call cap. Fail-open throughout: a missing handshake or any ioctl
        error ends the thread and the child keeps running.
        """
        listener = self._handshake()
        if self._psock is not None:
            with contextlib.suppress(Exception):
                self._psock.close()
        if listener is None:
            self._degrade("no usable seccomp handshake from child")
            return
        self._listener_fd = listener
        self._drain(listener)

    def _handshake(self) -> int | None:
        """Wait for the child's status datagram; return the listener fd or None."""
        if self._psock is None or self._stop_r is None:
            return None
        poller = select.poll()
        poller.register(self._psock.fileno(), select.POLLIN)
        poller.register(self._stop_r, select.POLLIN)
        events = dict(poller.poll(_START_HANDSHAKE_TIMEOUT * 1000))
        if self._stop_r in events or self._psock.fileno() not in events:
            return None  # stop requested, or the child never sent a status
        try:
            msg, ancdata, _flags, _addr = self._psock.recvmsg(
                1, socket.CMSG_SPACE(struct.calcsize("i"))
            )
        except OSError:
            return None
        if msg != _HANDSHAKE_OK:
            return None  # child signalled it could not install the filter
        return _extract_fd(ancdata)

    def _drain(self, fd: int) -> None:
        assert self._stop_r is not None and _libc is not None
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        poller.register(self._stop_r, select.POLLIN)
        dead = select.POLLHUP | select.POLLERR | select.POLLNVAL
        while True:
            try:
                events = dict(poller.poll())
            except Exception:  # noqa: BLE001 - any poll failure -> stop draining
                break
            if self._stop_r in events:
                break
            rev = events.get(fd, 0)
            if rev & dead:
                break
            if not rev & select.POLLIN:
                continue
            if not self._receive_and_continue(fd):
                break

    def _receive_and_continue(self, fd: int) -> bool:  # pragma: no cover
        """RECV one notification, answer CONTINUE, then dispatch it for audit.

        Returns ``True`` to keep draining, ``False`` to stop. Requires a live
        notify fd, so it is exercised by the ``seccomp``-marked end-to-end
        tests on a privileged host, not the portable unit suite.
        """
        assert _libc is not None
        size = self._sizes.notif
        notif = bytearray(size)  # MUST be zeroed before each RECV (else EINVAL)
        buf = (ctypes.c_char * size).from_buffer(notif)
        ctypes.set_errno(0)
        if _libc.ioctl(fd, self._recv_cmd, ctypes.addressof(buf)) != 0:
            # ENOENT: this target vanished between poll and recv — keep serving
            # others. Any other error: stop draining.
            return ctypes.get_errno() == errno.ENOENT
        notif_id, pid, nr, args = _parse_notif(notif)
        # Answer CONTINUE first so the child unblocks with minimal latency;
        # auditing the (already-permitted) syscall happens after.
        self._respond_continue(fd, notif_id)
        self._dispatch(pid, nr, args)
        return True

    def _respond_continue(self, fd: int, notif_id: int) -> None:
        resp = struct.pack(_RESP_PACK, notif_id, 0, 0, _SECCOMP_USER_NOTIF_FLAG_CONTINUE)
        rbuf = (ctypes.c_char * len(resp)).from_buffer_copy(resp)
        ctypes.set_errno(0)
        assert _libc is not None
        with contextlib.suppress(Exception):
            _libc.ioctl(fd, self._send_cmd, ctypes.addressof(rbuf))

    def _dispatch(self, pid: int, nr: int, args: tuple[int, ...]) -> None:
        self._count += 1
        if self._count <= self._cap:
            name = syscall_name(self._arch, nr)
            event = SyscallEvent(
                pid=pid,
                syscall=name,
                nr=nr,
                args=(args[0], args[1], args[2], args[3], args[4], args[5]),
            )
            _safe_call(self._on_event, event)
        elif self._count == self._cap + 1:
            _safe_call(self._on_overflow, pid)
        # beyond the cap: still CONTINUE every syscall, but stop emitting.

    def stop(self) -> None:
        """Signal the supervisor, join it, and release every fd. Idempotent."""
        if self._stopped:
            return
        self._stopped = True
        if self._stop_w is not None:
            with contextlib.suppress(Exception):
                os.write(self._stop_w, b"x")
        if self._thread is not None:
            self._thread.join(timeout=_STOP_JOIN_TIMEOUT)
        for attr in ("_listener_fd", "_stop_r", "_stop_w"):
            fd = getattr(self, attr)
            if fd is not None:
                with contextlib.suppress(Exception):
                    os.close(fd)
                setattr(self, attr, None)
        # Defensive: close any socketpair ends a failed/partial flow left open.
        for sock in (self._psock, self._csock):
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()
        self._psock = self._csock = None

    def _degrade(self, reason: str) -> None:
        _log.warning("seccomp-notify degraded: %s", reason)
        _safe_call(self._on_degraded, reason)


def _extract_fd(ancdata: list[tuple[int, int, bytes]]) -> int | None:
    for level, ctype, data in ancdata:
        if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
            fds = array("i")
            count = len(data) - (len(data) % fds.itemsize)
            fds.frombytes(data[:count])
            if len(fds) >= 1:
                return int(fds[0])
    return None


def _parse_notif(buf: bytearray) -> tuple[int, int, int, tuple[int, ...]]:
    notif_id, pid = struct.unpack_from("QI", buf, 0)
    (nr,) = struct.unpack_from("i", buf, _NOTIF_DATA_OFFSET)
    args = struct.unpack_from("6Q", buf, _NOTIF_DATA_OFFSET + _DATA_ARGS_OFFSET)
    return int(notif_id), int(pid), int(nr), tuple(int(a) for a in args)


def _safe_call(fn: Callable[..., object] | None, *fnargs: object) -> None:
    if fn is None:
        return
    with contextlib.suppress(Exception):
        fn(*fnargs)


# --- ambient per-call activation -------------------------------------------
#
# Relay.run() sets the active monitor for the duration of a single tool call;
# the local executor (shelltools) consults it when spawning. A ContextVar
# keeps concurrent tool calls isolated (each request task has its own context)
# without threading the monitor through every tool's zero-arg work closure.

_active: ContextVar[SeccompMonitor | None] = ContextVar("relay_shell_seccomp", default=None)


def set_active(monitor: SeccompMonitor | None) -> Token[SeccompMonitor | None]:
    return _active.set(monitor)


def get_active() -> SeccompMonitor | None:
    return _active.get()


def clear_active(token: Token[SeccompMonitor | None]) -> None:
    with contextlib.suppress(Exception):
        _active.reset(token)
