# ADR 0004: Automated TLS at the edge

- Status: Accepted
- Date: 2026-05-20

## Context

The HTTP transport binds `127.0.0.1` by design (ADR 0001, `docs/architecture.md`).
A reverse proxy in front terminates TLS and enforces the CIDR allowlist,
security headers, and access logging. Until now the deployment guide pointed
at a reference Caddyfile that operators had to hand-edit for their domain,
email, and CIDRs; the install path stopped at the Python service. That left
two recurring frictions for production deployers:

1. Bootstrapping the TLS edge correctly (CA contact, ACME directory,
   loopback upstream, security headers, log paths) was a manual checklist
   every time, with no validation step.
2. There was no documented automated-renewal story. Operators familiar with
   certbot tend to reach for a cron + reload pattern that adds moving parts
   we do not need.

## Decision

Adopt **Caddy's built-in ACME client** as the supported automated-TLS path,
and ship it as a turnkey installer:

- `deploy/Caddyfile` is now parameterized via Caddy's native `{$VAR:default}`
  env substitution: `RELAY_SHELL_EDGE_DOMAIN`, `RELAY_SHELL_EDGE_ACME_EMAIL`,
  `RELAY_SHELL_EDGE_CLIENT_CIDRS`, `RELAY_SHELL_EDGE_UPSTREAM`, and
  `RELAY_SHELL_EDGE_ACME_CA`. The same file works for every deployment; the
  config is the environment, not a fork of the Caddyfile.
- `deploy/install-edge.sh` installs Caddy from the official Cloudsmith apt
  repository when absent, writes a systemd drop-in
  (`/etc/systemd/system/caddy.service.d/relay-shell-edge.conf`) carrying
  those variables, validates the Caddyfile, and starts the service. It is
  idempotent and re-running it picks up edits to
  `/etc/relay-shell/relay-shell.env`.
- Let's Encrypt is the default ACME CA; `RELAY_SHELL_EDGE_ACME_CA` switches
  to the LE staging directory for dry runs, or to ZeroSSL / an internal CA
  if the deployment requires it. Caddy's existing ZeroSSL fallback on
  Let's Encrypt outage remains in effect.
- Renewals are driven by Caddy's internal scheduler (well before the 30-day
  threshold), not by cron. Certificates and account keys persist under
  Caddy's data directory across restarts.

## Consequences

- The supported edge becomes "install Caddy, set three env vars, run the
  script". Bootstrapping a new deployment no longer requires reading the
  Caddyfile line by line.
- No new code paths inside the Python service: TLS termination stays at the
  edge, the server still binds loopback, and the audit/policy layer is
  unchanged. The capability and security posture documented in ADR 0002 and
  ADR 0003 are preserved verbatim.
- Operators using a non-Caddy edge (nginx, HAProxy, an internal load
  balancer) are not constrained. The Caddyfile is the reference and the
  automated path; alternative proxies remain supported, with the operator
  responsible for their own ACME integration.
- The default CIDR allowlist in the rendered Caddyfile is loopback only.
  The installer warns when it is unchanged, so a misconfigured deployment
  fails closed (clients get a 403) rather than silently exposing the tool
  surface to the internet.

## Rejected

- **certbot + cron + reload**: more moving parts (separate package, hook
  scripts, a reload race during renewal) for a problem Caddy solves in
  process. Renewal failures would surface only at expiry, not at the next
  request.
- **Native TLS in the Python server**: would require key/cert lifecycle
  code inside the service, contradicts the loopback-bind architecture, and
  duplicates capability the edge proxy already owns. The proxy also handles
  CIDR allowlisting and security headers, which would otherwise migrate
  into the application.
- **Manual cert installation**: workable for a one-off deploy but loses the
  automated-renewal property the task requires.
