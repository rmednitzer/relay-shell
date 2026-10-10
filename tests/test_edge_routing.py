"""Exercise the shipped edge with Caddy, without TLS or a real relay service."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest


@pytest.mark.parametrize("allowlisted", [False, True])
def test_mcp_edge_cidr_gate(tmp_path: Path, allowlisted: bool) -> None:
    caddy = os.environ.get("CADDY_BINARY") or shutil.which("caddy")
    if not caddy:
        pytest.skip("requires Caddy on PATH or CADDY_BINARY")

    received: list[str] = []

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            received.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"upstream")

        def log_message(self, format: str, *args: object) -> None:
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    env = {key: value for key, value in os.environ.items() if not key.startswith("RELAY_SHELL_")}
    env.update(
        RELAY_SHELL_EDGE_DOMAIN=f"http://127.0.0.1:{port}",
        RELAY_SHELL_EDGE_ACME_EMAIL="test@example.org",
        RELAY_SHELL_EDGE_UPSTREAM=f"127.0.0.1:{upstream.server_port}",
    )
    if not allowlisted:
        # The loopback test client is outside this allowlist.
        env["RELAY_SHELL_EDGE_CLIENT_CIDRS"] = "192.0.2.0/24"
    template = (Path(__file__).resolve().parents[1] / "deploy" / "Caddyfile").read_text()
    # Keep routing unchanged. Isolate admin, persistence, access log and TLS.
    template = template.replace("{\n\temail", "{\n\tadmin off\n\tpersist_config off\n\temail", 1)
    template = template.replace(
        "/var/log/caddy/relay-shell-access.log", (tmp_path / "access.log").as_posix()
    )
    config = tmp_path / "Caddyfile"
    config.write_text(template)
    with (tmp_path / "caddy.log").open("w+") as log:
        process = subprocess.Popen(
            [caddy, "run", "--config", str(config), "--adapter", "caddyfile"],
            env=env,
            stdout=log,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        log.seek(0)
                        pytest.fail(f"Caddy did not start: {log.read()}")
                    time.sleep(0.05)
            for path in ("/mcp", "/mcp/", "/metrics"):
                conn = HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    conn.request("POST", path, headers={"X-Forwarded-For": "192.0.2.1"})
                    response = conn.getresponse()
                    assert response.status == (200 if allowlisted else 403)
                    assert response.read() == (b"upstream" if allowlisted else b"Forbidden")
                finally:
                    conn.close()
            assert received == (["/mcp", "/mcp/", "/metrics"] if allowlisted else [])
        finally:
            process.terminate()
            process.wait(timeout=10)
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=5)
