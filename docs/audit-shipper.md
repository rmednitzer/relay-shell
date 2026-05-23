# Shipping the audit log off-host

`relay-shell` writes one JSON object per tool call to a local audit
file (`/var/log/relay-shell/audit.jsonl` by default). On its own that
file is evidence only until the host is compromised: an attacker with
sufficient privilege can rotate it, mask it, or block writes. The
audit guarantee survives only if the records are shipped to a system
the operator controls separately from the relay host.

This guide gives one worked example each for three shipping shapes:
**Vector**, **Fluent Bit**, and **journalctl →
`systemd-journal-remote`**. Pick one — they overlap. The choice is
mostly operational (what is already in your stack, how the SIEM
ingests).

Cross-references:

- The audit-file contract and `chattr +a` posture: [`SECURITY.md`](../SECURITY.md)
  and [`docs/deployment.md`](deployment.md) §6.
- The runbook's "audit-the-audit" procedure: [`docs/runbook.md`](runbook.md) §2.3.

## 0. Common requirements

A shipper that meets the project's audit posture must:

1. **Preserve append-only.** The local file has `chattr +a` set
   (and `logrotate` drops/restores the attribute across rotation;
   see `deploy/logrotate/relay-shell`). The shipper reads, it does
   not rewrite. None of the three examples below modify the file.
2. **Preserve content.** No JSON re-encoding that drops fields, no
   field-level redaction beyond what `redaction.py` already did, no
   truncation. Records are already bounded by the relay
   (`output_sha256` + `output_len`, never the body).
3. **Survive log rotation.** The shipper must reopen the file after
   `logrotate` moves it. Vector and Fluent Bit use inode tracking
   (the source of truth across a rotation); the `tail -F`-based
   journal forwarder follows by name and reopens on rotation, which
   is acceptable here because the bundled `logrotate` config uses
   `create` (the new file is opened immediately, with no records
   buffered past the close of the old fd).
4. **Be observable.** Drops, retries, and back-pressure events must
   reach the operator. If the shipper silently buffers for hours,
   you have lost the property you were paying for.
5. **Send over TLS** to a remote collector. Examples below use TLS
   for transport; the listener-side configuration is out of scope
   (it is your SIEM / log-aggregator's responsibility).

The relay's installer creates `/var/log/relay-shell/audit.jsonl` as
`0600 relay-shell:relay-shell` (see `deploy/install.sh` and
`deploy/logrotate/relay-shell`). The shipper needs read access. Two
documented approaches:

- **Run the shipper as the `relay-shell` user.** The installer-created
  service account already has read access; just point the shipper's
  systemd unit at it. Used in the recipes below.
- **POSIX ACL.** Keep the shipper as its own user and grant explicit
  read with `setfacl -m u:<shipper>:r /var/log/relay-shell/audit.jsonl`
  plus a `setfacl -m u:<shipper>:rx /var/log/relay-shell`. Re-apply
  in `logrotate`'s `postrotate` script if you choose this path.

Do not weaken the file mode to grant group read; the `0600` default
is part of the on-host posture. The shipper writes nowhere under the
relay state directory in either approach.

---

## 1. Vector (recommended for most operators)

Vector (https://vector.dev) is a single static binary with a strict
config and end-to-end metrics. Pick this when you want one tool to
own the pipeline and surface back-pressure as Prometheus metrics out
of the box.

### Install

Use the official Timber-maintained apt repository. Avoid the
`curl ... | bash` one-liner; the explicit-keyring path below is
auditable and matches the project's security posture.

```bash
# 1. Fetch and verify the signing key. The fingerprint is published
#    at https://vector.dev/download/ - confirm it before importing.
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://repositories.timber.io/public/vector/gpg.3543DA2B.key \
  | sudo gpg --dearmor -o /etc/apt/keyrings/vector.gpg
sudo chmod 0644 /etc/apt/keyrings/vector.gpg

# 2. Add the apt source pinned to the keyring.
echo "deb [signed-by=/etc/apt/keyrings/vector.gpg] \
  https://repositories.timber.io/public/vector/deb/ubuntu $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/vector.list

# 3. Install.
sudo apt-get update && sudo apt-get install -y vector
```

### Config (`/etc/vector/vector.yaml`)

```yaml
# /etc/vector/vector.yaml
# Read the relay-shell audit log line-by-line, parse each record as
# JSON, and ship to a remote Vector / OTel / SIEM endpoint over TLS.

data_dir: /var/lib/vector

sources:
  relay_shell_audit:
    type: file
    include:
      - /var/log/relay-shell/audit.jsonl
    # Track by inode so rotation does not lose position. Vector
    # remembers checkpoints under data_dir.
    fingerprint:
      strategy: device_and_inode
    # Restart from beginning if the relay host was offline during a
    # rotation; checkpoint dedupes already-shipped records.
    read_from: beginning
    # Don't follow truncations - the file is append-only on disk.
    ignore_older_secs: 0
    # Bound memory.
    max_line_bytes: 1048576

transforms:
  parse:
    type: remap
    inputs: [relay_shell_audit]
    # One JSON object per line. If a line ever fails to parse,
    # forward it as-is with an .error field so the alert fires
    # rather than the record being dropped.
    source: |
      parsed, err = parse_json(.message)
      if err == null {
        . = merge(., parsed)
      } else {
        .parse_error = err
      }
      .host = get_hostname!()
      .service = "relay-shell"

sinks:
  remote_collector:
    type: vector
    inputs: [parse]
    address: collector.example.org:6000
    compression: true
    tls:
      enabled: true
      verify_certificate: true
      ca_file: /etc/vector/ca.pem
    healthcheck:
      enabled: true
    # Back-pressure: buffer to disk so an upstream outage doesn't
    # drop records. Alert when usage > 80%.
    buffer:
      type: disk
      max_size: 268435456  # 256 MiB
      when_full: block

  # Local Prometheus exporter so the shipper itself is observable.
  internal_metrics:
    type: prometheus_exporter
    inputs: [_internal_metrics_]
    address: 127.0.0.1:9598
```

### Run as the relay-shell user

Drop in a systemd unit override so Vector reads the audit file as
its owner:

```bash
sudo mkdir -p /etc/systemd/system/vector.service.d
sudo tee /etc/systemd/system/vector.service.d/override.conf >/dev/null <<'EOF'
[Service]
User=relay-shell
Group=relay-shell
EOF

# data_dir must be writable by relay-shell:
sudo install -d -m 0755 -o relay-shell -g relay-shell /var/lib/vector

sudo systemctl daemon-reload
sudo systemctl enable --now vector
```

If the operator prefers Vector to run as its own user (the upstream
default), grant read explicitly via POSIX ACL — see §0's
"common requirements" section.

### Verify

```bash
# Vector ran without config errors:
sudo systemctl status vector --no-pager
sudo journalctl -u vector -n 100 --no-pager | grep -iE "error|warn" || true

# Drive one tool call through the relay and confirm it lands at the
# remote side. From the relay host (Settings(audit_path=...) wins
# over the env var, so pass the path explicitly here):
python -c "
import asyncio
from relay_shell.config import Settings
from relay_shell.server import build_server
m = build_server(Settings(audit_path='/var/log/relay-shell/audit.jsonl'))
asyncio.run(m.call_tool('server_info', {}))
"

# Internal metrics: events received, retries, buffer usage.
curl -s http://127.0.0.1:9598/metrics | grep -E '^vector_(events|errors|buffer)'
```

### Troubleshoot

- **"permission denied" on the audit file.** Check
  `ls -l /var/log/relay-shell/audit.jsonl` — the file is created
  `0600 relay-shell:relay-shell` by `deploy/install.sh` and the
  bundled `logrotate` config preserves that mode. Use the systemd
  drop-in above (run Vector as `relay-shell`) or grant a POSIX ACL
  for the shipper's user. Do not chmod the file.
- **Records duplicated after restart.** Confirm `data_dir` is
  persistent and writable by the user running Vector (`relay-shell`
  in this recipe); the checkpoint lives there.
- **Records lost after rotation.** `logrotate` should be the bundled
  config (`deploy/logrotate/relay-shell`), which uses `create` so
  the inode changes only at rotate time. Vector's
  `device_and_inode` fingerprint follows the rename.

---

## 2. Fluent Bit (lightweight, broad output plugin set)

Fluent Bit (https://fluentbit.io) is the right choice if your
aggregator speaks Forward, Loki, OpenSearch, S3, or a cloud-native
sink natively, or if you want a smaller process footprint than
Vector. The configuration shape below is a thin file → JSON → output
pipeline.

### Install

Use the official Fluent Bit apt repository directly. Avoid the
`curl ... | sh` one-liner; the explicit path below is auditable.

```bash
# 1. Fetch and verify the signing key. The fingerprint is published
#    at https://docs.fluentbit.io/manual/installation/linux/ubuntu -
#    confirm it before importing.
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://packages.fluentbit.io/fluentbit.key \
  | sudo gpg --dearmor -o /etc/apt/keyrings/fluentbit.gpg
sudo chmod 0644 /etc/apt/keyrings/fluentbit.gpg

# 2. Add the apt source pinned to the keyring.
echo "deb [signed-by=/etc/apt/keyrings/fluentbit.gpg] \
  https://packages.fluentbit.io/ubuntu/$(lsb_release -cs) $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/fluent-bit.list

# 3. Install.
sudo apt-get update && sudo apt-get install -y fluent-bit
```

### Config (`/etc/fluent-bit/fluent-bit.conf`)

```ini
# /etc/fluent-bit/fluent-bit.conf
# Tail the relay-shell audit log, parse JSON, ship over Forward (TLS).

[SERVICE]
    Flush         5
    Daemon        Off
    Log_Level     info
    Parsers_File  parsers.conf
    HTTP_Server   On
    HTTP_Listen   127.0.0.1
    HTTP_Port     2020
    storage.path  /var/lib/fluent-bit/storage
    storage.sync  normal

[INPUT]
    Name              tail
    Path              /var/log/relay-shell/audit.jsonl
    # Inode-based tracking; rotation is transparent.
    Inotify_Watcher   true
    Refresh_Interval  5
    Rotate_Wait       30
    DB                /var/lib/fluent-bit/relay-shell-audit.db
    DB.Sync           normal
    Tag               relay_shell.audit
    Parser            relay_shell_audit
    # Skip lines that fail to parse - alert instead via the metrics endpoint.
    Skip_Long_Lines   On
    storage.type      filesystem

[FILTER]
    Name              modify
    Match             relay_shell.audit
    Add               host ${HOSTNAME}
    Add               service relay-shell

[OUTPUT]
    Name              forward
    Match             relay_shell.audit
    Host              collector.example.org
    Port              24224
    # Mandatory in production.
    tls               On
    tls.verify        On
    tls.ca_file       /etc/fluent-bit/ca.pem
    # Buffer to disk to survive upstream outages.
    storage.total_limit_size 256M
    Retry_Limit       False
    # Compression on the wire.
    Compress          gzip
```

And the parser (`/etc/fluent-bit/parsers.conf`):

```ini
[PARSER]
    Name        relay_shell_audit
    Format      json
    # The relay writes "ts" as ISO-8601 UTC.
    Time_Key    ts
    Time_Format %Y-%m-%dT%H:%M:%S.%LZ
    Time_Keep   On
```

### Run as the relay-shell user

Same pattern as the Vector recipe: a systemd drop-in moves Fluent Bit
under the same uid that owns the audit file.

```bash
sudo mkdir -p /etc/systemd/system/fluent-bit.service.d
sudo tee /etc/systemd/system/fluent-bit.service.d/override.conf >/dev/null <<'EOF'
[Service]
User=relay-shell
Group=relay-shell
EOF

# Storage dir must be writable by relay-shell:
sudo install -d -m 0755 -o relay-shell -g relay-shell /var/lib/fluent-bit/storage

sudo systemctl daemon-reload
sudo systemctl enable --now fluent-bit
```

POSIX ACL is the alternative if Fluent Bit must run as its own user
(see §0).

### Verify

```bash
sudo systemctl status fluent-bit --no-pager
sudo journalctl -u fluent-bit -n 100 --no-pager | grep -iE 'error|fail' || true

# HTTP metrics: events ingested, dropped, retried.
curl -s http://127.0.0.1:2020/api/v1/metrics/prometheus | grep -E '^fluentbit_(input|output)'

# End-to-end: drive a tool call, then watch the relay side and the
# remote receiver. On the receiver, you should see one record per
# call with the original fields plus `host`, `service`.
```

### Troubleshoot

- **"file rotation event lost"** — confirm `Rotate_Wait` is at least
  the time `logrotate` holds the old file before unlinking; 30s is
  the bundled value and matches the logrotate config.
- **Records replayed after restart** — `DB` must be on a persistent
  path with `DB.Sync normal` (not `off`); the position is otherwise
  lost on crash.

---

## 3. journalctl → `systemd-journal-remote`

Use this when the relay host already runs `systemd-journald` and the
ops org standard is "journal everything, ship the journal". This is
the lowest-friction shipper if you do not want a third-party agent on
the host, but it requires that the audit file be **also** delivered
to the journal (it is not, by default). The recipe below has two
parts:

1. A tiny forwarder unit `tail -F`s the audit file and pipes each
   line to journald. Each line is stored verbatim as the journal
   record's `MESSAGE` field — journald does **not** parse JSON into
   structured fields automatically; the JSON travels as a string and
   the receiving SIEM is responsible for re-parsing it. Pair with a
   `SYSLOG_IDENTIFIER` so the records are easy to query.
2. `systemd-journal-upload.service` runs on the relay host and
   pushes journal entries over HTTPS to a collector. The collector
   side runs `systemd-journal-remote.service` to receive — the two
   service names are easy to confuse, but they sit on different
   hosts.

### Forward the audit log into the journal

`/etc/systemd/system/relay-shell-audit-tail.service`:

```ini
[Unit]
Description=Forward relay-shell audit.jsonl into the systemd journal
After=relay-shell.service
Wants=relay-shell.service

[Service]
Type=simple
# tail -F follows rotation by name and reopens when logrotate's
# `create` directive lands a new file. SyslogIdentifier sets a stable
# tag in the journal; each MESSAGE is the original JSONL line verbatim
# - the receiving SIEM is responsible for JSON-parsing it.
ExecStart=/bin/sh -c 'exec /usr/bin/tail -n0 -F /var/log/relay-shell/audit.jsonl'
StandardOutput=journal
SyslogIdentifier=relay-shell-audit
# Run as the audit-file owner so the 0600 mode is respected without
# an ACL. The relay-shell account is unprivileged.
User=relay-shell
Group=relay-shell
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now relay-shell-audit-tail.service
```

Confirm in the journal:

```bash
journalctl -t relay-shell-audit -o cat -n 5
# Each line is the original JSONL record verbatim.
```

### Ship the journal to a remote collector

On the relay host, install and configure `systemd-journal-upload`:

```bash
sudo apt-get install -y systemd-journal-remote   # provides upload too
```

`/etc/systemd/journal-upload.conf`:

```ini
[Upload]
URL=https://journal-collector.example.org:19532
# Mutual TLS - the upload side authenticates with a client cert.
ServerKeyFile=/etc/ssl/private/journal-upload.key
ServerCertificateFile=/etc/ssl/journal-upload.crt
TrustedCertificateFile=/etc/ssl/journal-ca.crt
```

```bash
sudo systemctl enable --now systemd-journal-upload.service
```

On the collector host (out of scope for this repo; documented here
for completeness), `systemd-journal-remote.service` listens on
`19532/tcp` with a peer cert and writes to a local journal namespace
that the SIEM ingests.

### Verify

```bash
# 1. Forwarder is reading the file and emitting to the journal:
journalctl -u relay-shell-audit-tail --no-pager -n 5

# 2. Upload service is connected and not erroring:
systemctl status systemd-journal-upload --no-pager
journalctl -u systemd-journal-upload -n 100 --no-pager | grep -iE 'error|fail' || true

# 3. End-to-end: drive a relay tool call, then on the collector,
# confirm the matching record appears under SYSLOG_IDENTIFIER=relay-shell-audit.
```

### Troubleshoot

- **No records in the journal.** `tail -F` follows by name. If
  `logrotate` rotates without the `create` directive, `tail -F`
  reattaches to the new file but loses the records buffered in the
  old one until the FD closes. The bundled logrotate config uses
  `create` so this stays a non-issue.
- **Upload backs off without recovering.** Check the collector cert
  and that `19532/tcp` is reachable; `systemd-journal-upload`'s only
  remediation on connection error is exponential back-off with no
  on-disk spool.

---

## 4. Picking one

| Scenario                                                      | Pick                |
|---------------------------------------------------------------|---------------------|
| Standalone shipper, one tool owns the pipeline, Prom metrics  | Vector              |
| Fluent / Loki / OpenSearch / cloud-native sink, small footprint | Fluent Bit        |
| journald-centric ops org, no third-party agent on the host    | journal-remote      |
| You want the audit record AND the journal both shipped        | journal-remote + a copy of the JSONL via Vector or Fluent Bit |

The architectural property each preserves is the same: a remote
copy of every audit record, written without modifying the on-host
append-only file, with back-pressure that surfaces rather than
silently dropping. The relay's audit guarantee ends at the
filesystem; the shipper extends it to the rest of your stack.
