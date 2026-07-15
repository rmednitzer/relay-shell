"""Two-step confirmation broker for Tier-3 (irreversible) operations.

Adapts a plan -> authorize -> execute handshake (see
``docs/adr/0009-tier3-confirmation-broker.md``) into relay-shell's central
runner. **Opt-in and default-off**: the broker is constructed only when
``RELAY_SHELL_CONFIRM_TIER3`` is set, so with the default configuration
:meth:`Relay.run` never consults it and the audit record stays byte-identical
to today.

The flow, when enabled (every step lands on the normal audit stream):

1. **plan** - a Tier-3 tool call with no armed confirmation returns a
   single-use token bound to ``sha256(tool \\0 policy_text)`` with a TTL;
   ``work()`` does *not* run.
2. **arm** - ``operation_confirm(token)`` marks that token armed.
3. **execute** - re-issuing the *exact* same call finds the armed token,
   burns it (single-use), and proceeds to ``work()``.

The binding is the operation's hash - the tool name plus every
executor-visible byte the policy layer already saw - not a per-tool
parameter. So the gate is correct for every current and future
Tier-3-capable tool without threading a token through each wrapper, and it
lives in exactly one place (the central runner), mirroring how the deny list
and tier classifier already gate uniformly.

This is a *safeguard on top of* the tier/mode policy, never a replacement:
the deny list and mode checks still run first, and the retried call is
re-classified and re-admitted from scratch. Default-off means no posture
change; enabling it adds deliberate friction to irreversible operations so a
model persuaded in a single turn cannot fire one without a distinct second
step.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .util import sha256_hex

__all__ = ["Challenge", "ConfirmationBroker"]

# Bound the pending-token store so a client that keeps triggering plans (or a
# buggy caller) cannot grow it without limit. Far above any real interactive
# use; the sweep drops expired entries first, then the soonest-to-expire if
# still over budget.
_MAX_PENDING = 256


def _op_hash(tool: str, policy_text: str) -> str:
    """Stable identity of an operation.

    The tool name plus every executor-visible byte the policy layer saw,
    NUL-joined so ``(tool, text)`` cannot collide with ``(tool + text, "")``.
    Two calls confirm the *same* operation iff this value matches.
    """
    return sha256_hex(f"{tool}\x00{policy_text}")


@dataclass(frozen=True)
class Challenge:
    """The result of :meth:`ConfirmationBroker.plan`."""

    token: str
    ttl: int


@dataclass
class _Entry:
    op_hash: str
    tool: str
    expires_at: float  # monotonic-clock deadline
    armed: bool = False


class ConfirmationBroker:
    """In-memory, single-use, TTL-bounded confirmation tokens.

    Thread-safe: a :class:`threading.Lock` guards the store so the broker is
    safe even though every caller today runs on the event loop - the audit
    logger takes the same belt-and-braces posture for the seccomp-notify
    supervisor thread. State is process-local and ephemeral by design: a
    restart drops all pending tokens (fail-safe - a dropped token simply
    re-plans), so there is nothing to persist and no cross-restart replay.
    """

    def __init__(
        self,
        ttl: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_pending: int = _MAX_PENDING,
    ) -> None:
        self._ttl = max(1, int(ttl))
        self._clock = clock
        self._max_pending = max_pending
        self._lock = threading.Lock()
        self._by_token: dict[str, _Entry] = {}

    @property
    def ttl(self) -> int:
        return self._ttl

    def _sweep(self, now: float) -> None:
        """Drop expired tokens, then hard-bound the store. Caller holds lock."""
        expired = [tok for tok, e in self._by_token.items() if e.expires_at <= now]
        for tok in expired:
            del self._by_token[tok]
        if len(self._by_token) > self._max_pending:
            overflow = len(self._by_token) - self._max_pending
            for tok, _ in sorted(self._by_token.items(), key=lambda kv: kv[1].expires_at)[
                :overflow
            ]:
                del self._by_token[tok]

    def plan(self, tool: str, policy_text: str) -> Challenge:
        """Mint a fresh single-use token for ``(tool, policy_text)``.

        Each call issues a new token; a prior un-armed token for the same
        operation is left to expire on its own (the sweep reclaims it). The
        token is unguessable (128 bits) and only useful within its TTL and
        only for this exact operation.
        """
        now = self._clock()
        token = secrets.token_urlsafe(16)
        with self._lock:
            self._sweep(now)
            self._by_token[token] = _Entry(
                op_hash=_op_hash(tool, policy_text),
                tool=tool,
                expires_at=now + self._ttl,
            )
            self._sweep(now)  # re-bound after the insert
        return Challenge(token=token, ttl=self._ttl)

    def arm(self, token: str) -> bool:
        """Arm a pending token (the ``operation_confirm`` step).

        Returns ``True`` if the token exists and is unexpired (arming an
        already-armed token is idempotent), ``False`` for an unknown or
        expired token. Arming authorizes nothing on its own: the retried
        call is still re-classified and re-admitted by the policy layer
        before :meth:`consume` releases it.
        """
        now = self._clock()
        with self._lock:
            self._sweep(now)
            entry = self._by_token.get(token)
            if entry is None:
                return False
            entry.armed = True
            return True

    def consume(self, tool: str, policy_text: str) -> bool:
        """Burn an armed token matching ``(tool, policy_text)``.

        Returns ``True`` iff an unexpired *armed* token for this exact
        operation existed; single-use, so the token is removed on success. A
        pending-but-not-armed token does not satisfy this (the caller falls
        through to :meth:`plan` and re-challenges).
        """
        now = self._clock()
        target = _op_hash(tool, policy_text)
        with self._lock:
            self._sweep(now)
            match = next(
                (tok for tok, e in self._by_token.items() if e.armed and e.op_hash == target),
                None,
            )
            if match is None:
                return False
            del self._by_token[match]
            return True

    def pending(self) -> int:
        """Live (unexpired) token count - surfaced in ``server_info``."""
        now = self._clock()
        with self._lock:
            self._sweep(now)
            return len(self._by_token)
