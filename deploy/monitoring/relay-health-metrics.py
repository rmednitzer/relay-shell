#!/usr/bin/env python3
"""Emit bounded, non-sensitive Relay host and edge health metrics."""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

TIMEOUT_SECONDS = 8


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_timestamp(value: object) -> float:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp is not timezone-aware")
    return parsed.timestamp()


def request(url: str) -> tuple[int, object, bytes]:
    opener = build_opener(NoRedirect)
    req = Request(url, headers={"User-Agent": "relay-health-metrics/1"})
    try:
        with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
            return response.status, response.headers, response.read(262144)
    except HTTPError as exc:
        return exc.code, exc.headers, exc.read(262144)


def service_active(name: str) -> float:
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", name],
        check=False,
        timeout=5,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return 1.0 if result.returncode == 0 else 0.0


def main() -> int:
    domain = os.environ.get("RELAY_MONITOR_DOMAIN", "").strip()
    anchor_path = Path(
        os.environ.get(
            "RELAY_MONITOR_AUDIT_ANCHOR",
            "/var/log/relay-shell/latest-anchor.json",
        )
    )
    output_path = Path(
        os.environ.get(
            "RELAY_MONITOR_TEXTFILE",
            "/var/lib/prometheus/node-exporter/relay.prom",
        )
    )
    if not domain or any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
        for char in domain
    ):
        print("RELAY_MONITOR_DOMAIN is missing or invalid", file=sys.stderr)
        return 2

    metrics: list[tuple[str, str, float, str]] = []
    errors: list[str] = []

    def add(name: str, help_text: str, value: float, labels: str = "") -> None:
        metrics.append((name, help_text, float(value), labels))

    for unit in ("relay-shell.service", "caddy.service", "relay-audit-evidence.timer"):
        try:
            value = service_active(unit)
        except (OSError, subprocess.SubprocessError) as exc:
            value = 0.0
            errors.append(f"service {unit}: {exc}")
        add(
            "relay_service_up",
            "Whether a required Relay systemd unit is active.",
            value,
            f'{{service="{unit}"}}',
        )

    redirect_ok = metadata_ok = authorize_validation_ok = 0.0
    mcp_rejected = hsts_ok = security_headers_ok = 0.0
    try:
        code, headers, _ = request(f"http://{domain}/")
        redirect_ok = float(
            code in (301, 308) and headers.get("Location", "") == f"https://{domain}/"
        )
    except (OSError, ValueError) as exc:
        errors.append(f"HTTP redirect: {exc}")

    try:
        code, headers, body = request(f"https://{domain}/.well-known/oauth-authorization-server")
        document = json.loads(body)
        metadata_ok = float(
            code == 200
            and document.get("issuer") == f"https://{domain}/"
            and document.get("authorization_endpoint") == f"https://{domain}/authorize"
            and document.get("token_endpoint") == f"https://{domain}/token"
        )
        hsts = headers.get("Strict-Transport-Security", "").lower()
        hsts_ok = float("max-age=" in hsts and "includesubdomains" in hsts)
        csp = headers.get("Content-Security-Policy", "").lower()
        security_headers_ok = float(
            "default-src 'self'" in csp
            and "frame-ancestors 'none'" in csp
            and "base-uri 'none'" in csp
            and headers.get("X-Content-Type-Options", "").lower() == "nosniff"
            and headers.get("X-Frame-Options", "").upper() == "DENY"
            and headers.get("Referrer-Policy", "").lower() == "no-referrer"
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"OAuth metadata: {exc}")

    try:
        code, _, _ = request(f"https://{domain}/authorize")
        authorize_validation_ok = float(code == 400)
    except (OSError, ValueError) as exc:
        errors.append(f"OAuth authorization validation probe: {exc}")

    try:
        code, _, _ = request(f"https://{domain}/mcp")
        mcp_rejected = float(code == 401)
    except (OSError, ValueError) as exc:
        errors.append(f"MCP unauthorized probe: {exc}")

    add(
        "relay_http_redirect_ok",
        "Whether plain HTTP redirects to the canonical Relay HTTPS URL.",
        redirect_ok,
    )
    add(
        "relay_oauth_metadata_ok",
        "Whether Relay OAuth metadata is reachable and canonical.",
        metadata_ok,
    )
    add(
        "relay_authorize_validation_ok",
        "Whether an incomplete OAuth authorization request is rejected with HTTP 400.",
        authorize_validation_ok,
    )
    add(
        "relay_mcp_unauthenticated_rejected",
        "Whether an unauthenticated MCP request is rejected with HTTP 401.",
        mcp_rejected,
    )
    add(
        "relay_hsts_ok",
        "Whether the Relay HTTPS response advertises HSTS with includeSubDomains.",
        hsts_ok,
    )
    add(
        "relay_security_headers_ok",
        "Whether CSP, framing, MIME sniffing, and referrer protections are present.",
        security_headers_ok,
    )

    tls_ok = 0.0
    tls_not_after = 0.0
    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with (
            socket.create_connection((domain, 443), timeout=TIMEOUT_SECONDS) as raw,
            context.wrap_socket(raw, server_hostname=domain) as tls,
        ):
            certificate = tls.getpeercert()
        tls_not_after = ssl.cert_time_to_seconds(certificate["notAfter"])
        tls_ok = 1.0
    except (OSError, KeyError, ValueError, ssl.SSLError) as exc:
        errors.append(f"TLS certificate: {exc}")
    add(
        "relay_tls_handshake_ok",
        "Whether a verified TLS connection to the Relay edge succeeds.",
        tls_ok,
    )
    add(
        "relay_tls_certificate_not_after_seconds",
        "Unix timestamp at which the active Relay TLS certificate expires.",
        tls_not_after,
    )

    audit_valid = 0.0
    audit_generated = 0.0
    audit_latest = 0.0
    audit_records = 0.0
    audit_sequence = -1.0
    try:
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
        if anchor.get("evidence_type") != "relay_shell_audit_anchor":
            raise ValueError("unexpected evidence_type")
        audit_valid = float(anchor.get("valid") is True)
        audit_generated = parse_timestamp(anchor["generated_at"])
        audit_latest = parse_timestamp(anchor["latest_record_ts"])
        audit_records = float(anchor["records"])
        audit_sequence = float(anchor["latest_seq"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"audit anchor: {exc}")
    add(
        "relay_audit_chain_valid",
        "Whether the latest full retained Relay audit-chain verification succeeded.",
        audit_valid,
    )
    add(
        "relay_audit_evidence_generated_timestamp_seconds",
        "Unix timestamp when Relay audit evidence was last generated.",
        audit_generated,
    )
    add(
        "relay_audit_latest_record_timestamp_seconds",
        "Unix timestamp of the newest record covered by Relay audit evidence.",
        audit_latest,
    )
    add(
        "relay_audit_records",
        "Number of chained Relay audit records covered by the latest evidence.",
        audit_records,
    )
    add(
        "relay_audit_latest_sequence",
        "Latest Relay audit sequence number covered by the evidence.",
        audit_sequence,
    )

    add(
        "relay_monitor_collection_errors",
        "Number of exceptions encountered during the latest Relay health collection.",
        float(len(errors)),
    )
    add(
        "relay_monitor_collection_success",
        "Whether the latest Relay health collection completed without exceptions.",
        float(not errors),
    )
    add(
        "relay_monitor_generated_timestamp_seconds",
        "Unix timestamp when Relay host health metrics were generated.",
        time.time(),
    )

    lines: list[str] = []
    seen: set[str] = set()
    for name, help_text, value, labels in metrics:
        if name not in seen:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            seen.add(name)
        lines.append(f"{name}{labels} {value:.6f}")
    payload = "\n".join(lines) + "\n"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=".relay.",
            suffix=".prom",
            delete=False,
        ) as handle:
            temporary = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path = Path(temporary)
        temporary_path.chmod(0o644)
        temporary_path.replace(output_path)
    finally:
        if temporary:
            temporary_path = Path(temporary)
            if temporary_path.exists():
                temporary_path.unlink()

    for error in errors:
        print(error, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
