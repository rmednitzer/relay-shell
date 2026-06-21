# Authentication (OAuth 2.1)

> **Opt-in — disabled by default.** `relay-shell` runs with **no
> authentication** unless you turn it on. The OAuth 2.1 layer applies **only**
> to the HTTP transport and **only** when `RELAY_SHELL_AUTH_ENABLED=true`
> (default `false`, [`config.py`](../src/relay_shell/config.py) `auth_enabled`).
> The stdio transport has no network surface, so it has no auth layer — the
> transport itself is the trust boundary there.

This document explains how a client authenticates and, in particular, **how a
single client stays authenticated over time**. For the operational enable
steps (env vars, the `[http]` extra, the Caddy edge) see
[`deployment.md` §5](deployment.md). For the threat model see
[`SECURITY.md`](../SECURITY.md).

## Opt-in by default — and what "off" means

| `transport` | `auth_enabled` | Result |
|-------------|----------------|--------|
| `stdio` (default) | (ignored) | No OAuth layer; the local transport is the boundary. |
| `http` | `false` (default) | HTTP served **without** auth — you are relying entirely on the network edge (loopback bind + the Caddy CIDR allowlist in [`deployment.md` §4](deployment.md)). |
| `http` | `true` | OAuth 2.1 enforced: every tool call needs a valid bearer access token. |

Only when both conditions hold is the provider constructed
([`server.py`](../src/relay_shell/server.py): `if cfg.transport == "http" and
cfg.auth_enabled`). Authentication is therefore a deliberate operator choice,
never on implicitly. If you expose the HTTP transport beyond loopback, enable
it.

## The provider

`FileOAuthProvider` ([`auth/oauth.py`](../src/relay_shell/auth/oauth.py)) is an
OAuth 2.1 **authorization server**: dynamic client registration (DCR) with
optional single-client lockdown, PKCE (the SDK enforces the challenge),
short-lived authorization codes, and **rotating** refresh tokens. State is
three JSON files under `RELAY_SHELL_AUTH_STATE_DIR` — `clients.json`,
`codes.json`, `tokens.json` — created `0o700` and written `0o600`, and the
provider **refuses to start** if the state dir is group/other-accessible
(SEC-8). No database.

## Lifecycle

### 1. Register once → a persistent identity

The client performs DCR and receives a `client_id`, stored in `clients.json`
(`register_client`). The id is persistent — the client reuses it and never
needs to re-register.

### 2. Authorize with PKCE → a short-lived, one-shot code

`authorize` mints an authorization code bound to the client's
`code_challenge`, valid for `auth_code_ttl` (**default 300 s**). It is consumed
on first use (`exchange_authorization_code` deletes it) — single-use per
RFC 6749.

### 3. Exchange the code → access + refresh tokens

`_issue` mints two bearer tokens:

- an **access token**, lifetime `auth_access_ttl` (**default 3600 s = 1 h**);
- a **refresh token**, lifetime `auth_refresh_ttl` (**default 2 592 000 s =
  30 days**), stored under a `refresh:` key prefix.

### 4. Each request carries the access token

Every MCP call over HTTP sends `Authorization: Bearer <access-token>`; the SDK
calls `load_access_token` to validate it. Two guards matter there:

- a `refresh:`-prefixed string is **rejected** as an access token, so a refresh
  token cannot be replayed as an access token (token-type confusion, AUTH-1);
- expiry is enforced **lazily on read** — an expired token is deleted and the
  call gets `None` → 401. There is no background sweeper.

### 5. Staying authenticated past one hour — the rotation loop

This is the core of "how a single client stays authenticated." The access
token lives only an hour. When it expires, the client presents its **refresh
token** to `exchange_refresh_token`:

- the presented refresh token is **consumed** (rotation is single-use — the old
  one is deleted);
- a **brand-new** access + refresh pair is issued.

So the client rolls forward indefinitely as long as it refreshes at least once
per refresh-TTL window — **each rotation resets the 30-day window** on the new
refresh token. The client must persist the *latest* refresh token; if two
requests race a refresh, one wins and the other gets `invalid_grant`
(single-use is enforced by deleting the record before issuing).

```
register (once) ──> authorize+PKCE ──> code ──> exchange ──> access(1h) + refresh(30d)
                                                                  │
                              access expires (lazy 401)           │ every <30d
                                                                  ▼
                                              exchange_refresh_token (old refresh consumed)
                                                                  │
                                                                  ▼
                                                    new access(1h) + new refresh(30d) ──┐
                                                                  ▲                      │
                                                                  └──────────────────────┘
```

### 6. Persistence across restarts

Token state is file-backed, so a server restart does **not** log the client
out — the access and refresh tokens are still valid on disk. (The state dir is
`0o700`, fail-closed.)

### 7. When a full re-authentication is required

Only if the client is idle **longer than the refresh TTL (30 days by
default)**: the refresh token has expired and the client must run the PKCE
authorize flow again (step 2). It still does **not** re-register — the
`client_id` persists, which matters under single-client lockdown (below).

### 8. Revocation

`revoke_token` removes the presented token. Revocation does **not** cascade
between an access token and its paired refresh token (RFC 7009 leaves that
unspecified and the provider opts out, in both directions — see the
`test_revoke_*` cases). To fully cut a client off, revoke both, or let the
short access TTL expire and revoke the refresh token.

## Single-client lockdown

With `RELAY_SHELL_AUTH_SINGLE_CLIENT=true` (**the default**), DCR is frozen
once the first client registers:

- a **new** `client_id` is refused (`Dynamic client registration is closed`);
- the **existing** client cannot be **modified** — in particular its
  `redirect_uri` cannot be overwritten, which would otherwise let someone who
  learned the `client_id` steer the next authorization code to their own URL
  (AUTH-2);
- a **byte-identical** re-registration is a harmless no-op, so a client that
  re-runs DCR with the same metadata is not broken.

Set it to `false` for a multi-client deployment, where ordinary DCR (including
metadata updates) applies.

## Defaults at a glance

| Setting | Env var | Default | Meaning |
|---------|---------|---------|---------|
| Enabled | `RELAY_SHELL_AUTH_ENABLED` | `false` | Master switch (HTTP transport only). |
| Single client | `RELAY_SHELL_AUTH_SINGLE_CLIENT` | `true` | Freeze DCR after the first client. |
| Access TTL | `RELAY_SHELL_AUTH_ACCESS_TTL` | `3600` (1 h) | Bearer access-token lifetime. |
| Refresh TTL | `RELAY_SHELL_AUTH_REFRESH_TTL` | `2592000` (30 d) | Refresh-token lifetime (resets on each rotation). |
| Code TTL | `RELAY_SHELL_AUTH_CODE_TTL` | `300` (5 min) | Authorization-code lifetime (single-use). |
| State dir | `RELAY_SHELL_AUTH_STATE_DIR` | `/var/lib/relay-shell/oauth` | `clients.json` / `codes.json` / `tokens.json` (`0o700`/`0o600`). |
| Issuer | `RELAY_SHELL_AUTH_ISSUER` | `https://localhost:8080` | Advertised issuer URL. |

## Security model — why opt-in

`relay-shell` executes commands with the full privileges of its service
account (ADR 0002). The OAuth layer is one of the *compensating controls*, not
a sandbox. It is opt-in because the supported deployment shapes differ:

- **stdio** (e.g. a local MCP client): no network surface, no auth needed.
- **HTTP behind a trusted edge**: the Caddy CIDR allowlist + loopback bind may
  be the operator's chosen boundary; OAuth adds defence in depth.
- **HTTP exposed more widely**: enable OAuth — it is required, not optional, in
  that posture.

Because the default transport is stdio and the default for `auth_enabled` is
`false`, a fresh install never silently stands up an unauthenticated network
listener: you choose HTTP, and you choose whether to authenticate it. When you
do expose HTTP, the deployment checklist in [`deployment.md`](deployment.md)
treats the edge controls **and** OAuth as required.

## References

- Operational setup: [`deployment.md` §5](deployment.md) (enable) and §4 (edge).
- Threat model and trust boundary: [`SECURITY.md`](../SECURITY.md).
- Runtime/no-sandbox posture: [ADR 0002](adr/0002-no-sandbox-full-access.md).
- Adding another provider: [`runbook.md` §6.3](runbook.md).
- RFCs: OAuth 2.1 (draft), PKCE (RFC 7636), token revocation (RFC 7009),
  resource indicators (RFC 8707), bearer usage (RFC 6750).
