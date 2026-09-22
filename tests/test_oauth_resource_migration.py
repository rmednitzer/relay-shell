"""Synthetic offline grant-adoption tests; no real credentials are used."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "bind_legacy", Path(__file__).parents[1] / "scripts/bind-legacy-oauth.py"
)
assert spec and spec.loader
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def records():
    return {
        "opaque": {
            "token": "opaque",
            "client_id": "client",
            "scopes": ["mcp:tools"],
            "expires_at": 200,
        },
        "refresh:renew": {
            "token": "renew",
            "client_id": "client",
            "scopes": ["mcp:tools"],
            "expires_at": 300,
        },
    }


def test_explicit_migration_preserves_token_scopes_and_expiry():
    before = records()
    after, counts = migration.bind_records(before, {"client": {}}, "https://example.org/mcp", 100)
    assert counts["bound_access"] == 1 and counts["bound_refresh"] == 1
    for key in before:
        assert after[key] == {**before[key], "resource": "https://example.org/mcp"}
        assert "resource" not in before[key]
    again, counts2 = migration.bind_records(after, {"client": {}}, "https://example.org/mcp", 100)
    assert again == after and counts2["already_bound"] == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_id", "unregistered"),
        ("token", "tampered"),
        ("scopes", ["admin"]),
        ("expires_at", "200"),
        ("resource", "https://foreign.example/mcp"),
    ],
)
def test_ambiguous_or_foreign_grant_refuses_migration(field, value):
    tokens = records()
    tokens["opaque"][field] = value
    with pytest.raises(ValueError):
        migration.bind_records(tokens, {"client": {}}, "https://example.org/mcp", 100)


def test_expired_grants_are_not_reactivated():
    tokens = records()
    after, counts = migration.bind_records(tokens, {"client": {}}, "https://example.org/mcp", 400)
    assert after == tokens and counts["expired"] == 2
