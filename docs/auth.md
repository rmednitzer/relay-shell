# Authentication (OAuth 2.1)

> **Opt-in — disabled by default.** `relay-shell` runs with **no
> authentication** unless you turn it on. The OAuth 2.1 layer applies **only**
> to the HTTP transport and **only** when `RELAY_SHELL_AUTH_ENABLED=true`
> (default `false`, [`config.py`](https://github.com/rmednitzer/relay-shell/blob/main/src/relay_shell/config.py) `auth_enabled`).
> The stdio transport has no network surface, so it has no auth layer — the
> transport itself is the trust boundary there.

This document explains how a client authenticates and, in particular, **how a
single client stays authenticated over time**. For the operational enable
steps (env vars, the Caddy edge) see
[`deployment.md` §5](deployment.md). For the threat model see
[`SECURITY.md`](https://github.com/rmednitzer/relay-shell/blob/main/SECURITY.md).

## Opt-in by default — and what "off" means

| `transport` | `auth_enabled` | Result |
|-------------|----------------|--------|
| `stdio` (default) | (ignored) | No OAuth layer; the local transport is the boundary. |
| `http` | `false` (default) | HTTP served **without** auth — you are relying entirely on the network edge (loopback bind + the Caddy CIDR allowlist in [`deployment.md` §4](deployment.md)). |
| `http` | `true` | OAuth 2.1 enforced: every tool call needs a valid bearer access token. |

Only when both conditions hold is the provider constructed
([`server.py`](https://github.com/rmednitzer/relay-shell/blob/main/src/relay_shell/server.py): `if cfg.transport == "http" and
cfg.auth_enabled`). Authentication is therefore a deliberate operator choice,
never on implicitly. If you expose the HTTP transport beyond loopback, enable
it.

## The provider

`FileOAuthProvider` ([`auth/oauth.py`](https://github.com/rmednitzer/relay-shell/blob/main/src/relay_shell/auth/oauth.py)) is an
OAuth 2.1 **authorization server**: dynamic client registration (DCR) with
optional single-client lockdown, PKCE (the SDK enforces the challenge),
short-lived authorization codes, and **rotating** refresh tokens. State is
four JSON files under `RELAY_SHELL_AUTH_STATE_DIR` — `clients.json`,
`approvals.json`, `codes.json`, `tokens.json` — created `0o700` and written `0o600`, and the
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
  call gets `None` → 401. There is no background sweeper, so expired records that
  are never presented are dropped whenever a new token or authorization code is
  written, which bounds the files;
- secrets are **stored as hashes**: `tokens.json` and `codes.json` are keyed by
  `sha256:<hex>` (refresh tokens as `refresh:sha256:<hex>`) and hold no raw token or
  code, so a copy of the state directory yields nothing usable as a bearer
  credential. A presented secret that is not plain URL-safe base64 (for instance a
  stored `sha256:...` key replayed as a token) is refused before any lookup. Files
  from before hashing are rewritten on the next start; a record that carries no
  matching `resource` binding (issued before resource binding, see below) is refused
  rather than honoured;
- the whole-file read that backs each authenticated request runs on a worker
  thread, so it does not block the event loop.

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

#### Reuse of a rotated-out refresh token

Rotation leaves a marker (`sha256:spent:<hash of the token>`, never the token, carrying the
client id and the token's own expiry) in `tokens.json`. If the same refresh token is
presented again, two parties hold it, the legitimate client and whoever copied it:

- within 10 seconds of the rotation it is only refused (`invalid_grant`): two requests that
  loaded the same token, or a retry that crossed the rotation, are a race, not theft;
- later, **all access and refresh tokens of that client are revoked** and the event is logged
  (`refresh token reuse for client ...`), so the previous access token no longer works for
  its remaining lifetime and the client has to authorize again;
- a replay by a different `client_id` is refused and revokes nothing.

STPA trace (authority handover). Losses: L-1 a stolen refresh token keeps minting access
tokens, L-2 a legitimate client is locked out by a false alarm. Hazards: H-1 a token that was
rotated away is still useful to its holder, H-2 revocation fires on a benign race.
Constraints: SC-1 a spent token cannot extend a session unnoticed, SC-2 a race inside the
grace window never revokes, SC-3 one client's alarm never touches another client's tokens.
Unsafe control actions: UCA-1 not provided, reuse is not detected (tests:
`test_replayed_refresh_token_after_the_grace_window_revokes_the_client`); UCA-2 provided
unsafely, a race revokes (`test_replay_inside_the_grace_window_is_refused_but_revokes_nothing`);
UCA-3 provided unsafely, a replay by client B revokes client A
(`test_a_replay_by_another_client_id_does_not_revoke_the_owner`). Scenario CS-1: the thief
refreshes first and the real client's next refresh is the replay, so the thief's family is
revoked together with the client's (the client re-authorizes, which is the intended outcome).
Limits: a thief who refreshes and whose copy is never replayed is invisible, and a theft
within the 10 s grace window is not caught; both are inherent to rotation without
sender-constraining. `client_secret` values are stored as the SDK compares them (raw) in
`clients.json` (0600, state dir 0700).

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

### 9. Resource binding (RFC 8707)

Every authorization code, access token and refresh token is bound to **this server's
resource identifier**: `RELAY_SHELL_AUTH_RESOURCE_URL`, or the issuer URL when that is
empty (so upgrading does not change the identifier discovery already advertises). Set it
to the exact public MCP endpoint in a new deployment.

- A request with no `resource` parameter is bound to the configured resource; a `resource`
  that names anything else is refused (`invalid_target` on `/authorize` and `/token`), and
  so is a repeated `resource` parameter at the token endpoint (a small middleware checks it
  because the SDK parses but does not pass it on).
- Code and refresh exchange use the **stored** grant (scopes and resource), never
  caller-supplied scopes or audience, and `load_access_token` validates the bound resource
  of every bearer token (`validate_token_resource`).
- A stored record whose `resource` is missing or different fails closed: an access token
  answers 401, a refresh or code exchange answers `invalid_grant`. There is no automatic
  grandfathering and no timed fail-open mode, so grants issued before this binding existed
  must be re-authorized (or rebound offline, see
  [`runbook.md` §10](runbook.md)). Do not change the issuer or resource identifier in the
  same step as that migration.

## Operator approval

Dynamic client registration is open to whoever can reach `/register` (the Caddy
template exposes it so a remote MCP client can onboard itself), and the
authorization endpoint has no login step: it issues a code to any *registered*
client that presents a valid PKCE challenge and its registered `redirect_uri`.
Registration alone therefore used to be enough to obtain a token, which is shell
execution as the service user. The first party to register won, and a client store
that read as empty (a missing or corrupt `clients.json`) reopened the race.

With `RELAY_SHELL_AUTH_REQUIRE_APPROVAL=true` (**the default**) a newly registered
client is **pending**: `/register` still succeeds, but `/authorize` answers
`access_denied` until the operator approves the client **on the host** that owns
the state directory:

```bash
relay-shell --auth-list                    # client_id, approved|pending, redirect URIs
relay-shell --auth-approve <client_id>     # takes effect on the next /authorize, no restart
relay-shell --auth-reject  <client_id>     # remove it with its approval, codes and tokens
```

Onboarding a connector is therefore: add it in the MCP client (this registers it),
read its `client_id` and redirect URI from `--auth-list`, check that they are the
client you just added, then approve it. A pending client you do not recognise is
the attack this gate exists to stop: reject it. Under single-client lockdown,
rejecting the only client also reopens registration, so the intended client can
register. The server logs each refused authorization with the command to run.

- **Upgrading.** Clients already on disk when `approvals.json` does not yet exist
  are carried over as approved (listed as "carried over"), so an upgrade does not
  lock the existing client out. Only clients registered afterwards are pending.
- **Fail closed.** A state file that exists but cannot be parsed is an error, not an
  empty store: `/register` refuses (and leaves `clients.json` untouched) and
  `--auth-list` reports it; an unreadable `approvals.json` approves nothing.
- **Opting out.** `RELAY_SHELL_AUTH_REQUIRE_APPROVAL=false` restores the previous
  behavior. Do that only where the edge itself authenticates the caller (a client
  certificate or an identity-aware proxy in front of `/register` and `/authorize`).

### Residual: approval gates the client, not each authorization

Approval is a one-time decision about a *client*. For an approved client the
authorization endpoint still has no login step, and the Caddy template leaves `/authorize`,
`/register`, `/token` and `/revoke` public (EDGE-1) so remote connectors can onboard. Anyone
who can reach `/authorize` and presents the `client_id`, a PKCE challenge and the exact
registered `redirect_uri` receives a code, and `/token` redeems it. A confidential client
(`client_secret_*`) additionally needs its secret. A *public* client
(`token_endpoint_auth_method=none`) with a loopback redirect such as
`http://localhost:PORT/cb` is the weak case: whoever holds its `client_id` can run their own
listener on that port and obtain a token. A `client_id` is not a secret; it appears in
authorize URLs and in the edge access log.

What bounds this (accepted, 2026-10-14, A14-A2): the MCP endpoint and every other operational
path stay behind the edge CIDR gate (`RELAY_SHELL_EDGE_CLIENT_CIDRS`), so a token minted from
outside the allowlist cannot be used from there. The exposure that remains is hosts *inside*
the allowlist, and any deployment whose allowlist is broad (a whole VPN range, or
`0.0.0.0/0`), where the approval gate is then the only control. Therefore:

- keep `RELAY_SHELL_EDGE_CLIENT_CIDRS` to the specific hosts that run MCP clients;
- approve only clients you recognise, and `--auth-reject` anything else (it also revokes its
  codes and tokens);
- for a machine-only deployment with no browser flow, move the `/authorize` handle below
  `@blocked` in the Caddyfile (see the EDGE-1 comment) so it is CIDR-gated too;
- treat the `client_id` of a loopback-redirect public client as sensitive.

### Residual: sessions and forwards are shared between clients

Approval admits a client to the whole tool surface. `shell_spawn` / `ssh_spawn` sessions and
`ssh_forward` listeners carry no owner, so with several approved clients each one sees all
sessions in `session_list` and can `session_send`, `session_recv` and `session_kill` any of
them by id (accepted 2026-10-14, A14-RS). A second client could open its own shell anyway, so
the exposure is cross-client visibility of one operator's terminal output (including anything
typed at a secret prompt), not extra capability. Where clients must not see each other's
terminals, run a separate instance per trust domain.

## Single-client lockdown

With `RELAY_SHELL_AUTH_SINGLE_CLIENT=true` (**the default**), DCR is frozen
once the first client registers:

- a **new** `client_id` is refused (`Dynamic client registration is closed`);
- the **existing** client cannot be **modified** — in particular its
  `redirect_uri` cannot be overwritten, which would otherwise let someone who
  learned the `client_id` steer the next authorization code to their own URL
  (AUTH-2);
- every `/register` call is minted a fresh `client_id` by the SDK, so under
  lockdown a repeated registration is always a *new* client and is refused with
  an RFC 7591 `400 invalid_client_metadata` (it used to surface as an HTTP 500).
  The provider itself still treats a byte-identical re-registration of an
  existing `client_id` as a no-op.

Set it to `false` for a multi-client deployment, where ordinary DCR (including
metadata updates) applies.

## Defaults at a glance

| Setting | Env var | Default | Meaning |
|---------|---------|---------|---------|
| Enabled | `RELAY_SHELL_AUTH_ENABLED` | `false` | Master switch (HTTP transport only). |
| Single client | `RELAY_SHELL_AUTH_SINGLE_CLIENT` | `true` | Freeze DCR after the first client. |
| Require approval | `RELAY_SHELL_AUTH_REQUIRE_APPROVAL` | `true` | A new client is pending until `relay-shell --auth-approve`. |
| Access TTL | `RELAY_SHELL_AUTH_ACCESS_TTL` | `3600` (1 h) | Bearer access-token lifetime. |
| Refresh TTL | `RELAY_SHELL_AUTH_REFRESH_TTL` | `2592000` (30 d) | Refresh-token lifetime (resets on each rotation). |
| Code TTL | `RELAY_SHELL_AUTH_CODE_TTL` | `300` (5 min) | Authorization-code lifetime (single-use). |
| State dir | `RELAY_SHELL_AUTH_STATE_DIR` | `/var/lib/relay-shell/oauth` | `clients.json` / `approvals.json` / `codes.json` / `tokens.json` (`0o700`/`0o600`). |
| Issuer | `RELAY_SHELL_AUTH_ISSUER` | `https://localhost:8080` | Advertised issuer URL. |
| Resource URL | `RELAY_SHELL_AUTH_RESOURCE_URL` | empty (= the issuer URL) | The exact public MCP endpoint that tokens are bound to (RFC 8707). |

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
- Threat model and trust boundary: [`SECURITY.md`](https://github.com/rmednitzer/relay-shell/blob/main/SECURITY.md).
- Runtime/no-sandbox posture: [ADR 0002](adr/0002-no-sandbox-full-access.md).
- Adding another provider: [`runbook.md` §6.3](runbook.md).
- RFCs: OAuth 2.1 (draft), PKCE (RFC 7636), token revocation (RFC 7009),
  resource indicators (RFC 8707), bearer usage (RFC 6750).
