"""Operator-side management of OAuth clients: list, approve, reject.

Dynamic client registration is open to whoever can reach ``/register`` and the
authorization endpoint has no login step, so a newly registered client is
*pending* until the operator approves it here, on the host that owns the state
directory (``relay-shell --auth-list`` / ``--auth-approve`` / ``--auth-reject``).
These helpers operate on the same files the running server uses, so an approval
takes effect on the client's next ``/authorize`` without a restart.

Concurrency: the CLI and the server are separate processes with no shared lock. A
lost update is fail-safe in every case (a lost approval leaves the client pending,
a lost registration makes the client re-register), so none is guarded further.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oauth import _Store

__all__ = ["ClientRow", "approve_client", "list_clients", "reject_client"]


@dataclass(frozen=True)
class ClientRow:
    client_id: str
    status: str  # "approved" | "pending"
    redirect_uris: tuple[str, ...]
    legacy: bool  # carried over as approved when approvals were introduced


def _stores(state_dir: str) -> tuple[_Store, _Store, _Store, _Store]:
    base = Path(state_dir).expanduser()
    if not base.is_dir():
        raise FileNotFoundError(f"OAuth state directory not found: {base}")
    return (
        _Store(base / "clients.json"),
        _Store(base / "approvals.json"),
        _Store(base / "codes.json"),
        _Store(base / "tokens.json"),
    )


def list_clients(state_dir: str) -> list[ClientRow]:
    """Every registered client with its approval status. Raises
    :class:`StoreUnreadableError` if a state file exists but cannot be parsed."""
    clients, approvals, _codes, _tokens = _stores(state_dir)
    approved = approvals.load(strict=True)
    rows: list[ClientRow] = []
    for cid, rec in sorted(clients.load(strict=True).items()):
        approval = approved.get(cid)
        is_approved = isinstance(approval, dict) and approval.get("approved") is True
        uris = rec.get("redirect_uris") if isinstance(rec, dict) else None
        rows.append(
            ClientRow(
                client_id=cid,
                status="approved" if is_approved else "pending",
                redirect_uris=tuple(str(u) for u in uris) if isinstance(uris, list) else (),
                legacy=bool(isinstance(approval, dict) and approval.get("legacy")),
            )
        )
    return rows


def approve_client(state_dir: str, client_id: str) -> bool:
    """Approve a registered client. ``False`` if no such client is registered."""
    clients, approvals, _codes, _tokens = _stores(state_dir)
    if client_id not in clients.load(strict=True):
        return False
    data = approvals.load(strict=True)
    data[client_id] = {"approved": True}
    approvals.save(data)
    return True


def reject_client(state_dir: str, client_id: str) -> bool:
    """Remove a client together with its approval, codes and tokens.

    ``False`` if no such client is registered. With single-client lockdown on,
    this also reopens registration (the store is empty again), so the operator
    can let the intended client register.
    """
    clients, approvals, codes, tokens = _stores(state_dir)
    registered = clients.load(strict=True)
    if client_id not in registered:
        return False
    del registered[client_id]
    clients.save(registered)
    approved = approvals.load(strict=True)
    approved.pop(client_id, None)
    approvals.save(approved)
    for store in (codes, tokens):
        data: dict[str, Any] = store.load()
        kept = {k: v for k, v in data.items() if not _belongs_to(v, client_id)}
        if len(kept) != len(data):
            store.save(kept)
    return True


def _belongs_to(record: Any, client_id: str) -> bool:
    return isinstance(record, dict) and record.get("client_id") == client_id
