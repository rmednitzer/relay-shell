# Relay host monitoring

This deployment adds host metrics without exposing the exporter publicly.

- Install the distribution-signed prometheus-node-exporter package at an
  operator-pinned version.
- Copy the exporter hardening drop-in to
  /etc/systemd/system/prometheus-node-exporter.service.d/override.conf.
  The checked-in deployment binds the verified Relay Tailscale address only.
- Create /var/lib/prometheus/node-exporter as relay-shell:prometheus mode 0750.
  The health collector writes one atomic, non-sensitive relay.prom file;
  node_exporter only reads it.
- Install relay-health-metrics.py as /usr/local/libexec/relay-health-metrics,
  its service/timer under /etc/systemd/system, and a root-owned mode 0644
  /etc/relay-shell/relay-monitoring.env based on the example.
- Restrict TCP/9100 in the host firewall to the monitoring scraper's verified
  Tailscale source address. Binding to the Tailscale address remains mandatory
  defense in depth.
- Validate with systemd-analyze verify, ss -lntp, a local Tailscale-address
  scrape, and a rejected connection to the public address.

The collector validates the Relay services, canonical HTTP redirect, OAuth
metadata, expected unauthenticated MCP rejection, HSTS, verified TLS
certificate expiry, and the latest retained audit-chain evidence anchor. It
never exports OAuth tokens, command data, certificate keys, or audit payloads.

Rollback: disable the health timer and exporter, restore the backed-up systemd
and nftables files, reload systemd/nftables, and remove the distribution
package only after confirming no other service depends on it.

The exact persistent firewall line is tracked in nftables.conf.snippet. On this
host it is installed inside the input chain in /etc/nftables.conf after invalid
state rejection and before the final drop. Validate the complete file with
nft -c -f /etc/nftables.conf before changing the live ruleset.
