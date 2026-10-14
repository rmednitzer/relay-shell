"""Exercise the shipped edge with Caddy, without TLS or a real relay service."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _caddy(tmp_path: Path) -> str:
    """A Caddy that understands ``persist_config``, or skip (the apt package is 2.6)."""
    caddy = os.environ.get("CADDY_BINARY") or shutil.which("caddy")
    if not caddy:
        pytest.skip("requires Caddy on PATH or CADDY_BINARY")
    probe = tmp_path / "probe.Caddyfile"
    probe.write_text("{\n\tpersist_config off\n}\n")
    adapted = subprocess.run(
        [caddy, "adapt", "--config", str(probe), "--adapter", "caddyfile"],
        capture_output=True,
        check=False,
    )
    if adapted.returncode != 0:
        pytest.skip("requires a Caddy that supports the persist_config global option (2.7+)")
    return caddy


@contextmanager
def _edge(
    tmp_path: Path, caddy: str, *, allowlisted: bool, upstream_handler: type[BaseHTTPRequestHandler]
) -> Iterator[tuple[int, Path]]:
    """Run the shipped Caddyfile on a free port in front of ``upstream_handler``."""
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), upstream_handler)
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
    template = (ROOT / "deploy" / "Caddyfile").read_text()
    # Keep routing unchanged. Isolate admin, persistence, access log and TLS.
    template = template.replace("{\n\temail", "{\n\tadmin off\n\tpersist_config off\n\temail", 1)
    access_log = tmp_path / "access.log"
    template = template.replace("/var/log/caddy/relay-shell-access.log", access_log.as_posix())
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
            yield port, access_log
        finally:
            process.terminate()
            process.wait(timeout=10)
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=5)


def _recording_upstream(received: list[tuple[str, int]]) -> type[BaseHTTPRequestHandler]:
    class Upstream(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            received.append((self.path, len(body)))
            if self.path.split("?", 1)[0] == "/authorize":
                self.send_response(302)
                self.send_header("Location", "https://client.example/cb?code=SECRETCODE&state=s")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"upstream")

        do_POST = do_GET = _handle

        def log_message(self, format: str, *args: object) -> None:
            pass

    return Upstream


@pytest.mark.parametrize("allowlisted", [False, True])
def test_mcp_edge_cidr_gate(tmp_path: Path, allowlisted: bool) -> None:
    caddy = _caddy(tmp_path)
    received: list[tuple[str, int]] = []
    with _edge(
        tmp_path, caddy, allowlisted=allowlisted, upstream_handler=_recording_upstream(received)
    ) as (port, _log):
        for path in ("/mcp", "/mcp/", "/metrics"):
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("POST", path, headers={"X-Forwarded-For": "192.0.2.1"})
                response = conn.getresponse()
                assert response.status == (200 if allowlisted else 403)
                assert response.read() == (b"upstream" if allowlisted else b"Forbidden")
            finally:
                conn.close()
    assert [p for p, _ in received] == (["/mcp", "/mcp/", "/metrics"] if allowlisted else [])


def test_public_oauth_paths_cap_the_request_body(tmp_path: Path) -> None:
    """A14-D10: /register, /token and friends are open to any address, so their body is capped."""
    caddy = _caddy(tmp_path)
    received: list[tuple[str, int]] = []
    with _edge(
        tmp_path, caddy, allowlisted=False, upstream_handler=_recording_upstream(received)
    ) as (port, _log):
        for path in ("/register", "/token", "/revoke"):
            small, big = b"x" * 1024, b"x" * (64 * 1024 + 4096)
            for body, expected in ((small, 200), (big, 413)):
                conn = HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    conn.request("POST", path, body=body)
                    assert conn.getresponse().status == expected, (path, len(body))
                finally:
                    conn.close()
    sizes = {(p, n) for p, n in received}
    assert ("/register", 1024) in sizes and not any(n > 64 * 1024 for _, n in received)


def test_access_log_does_not_record_the_authorize_redirect_target(tmp_path: Path) -> None:
    """A14-D10: the 302 Location carries the authorization code."""
    caddy = _caddy(tmp_path)
    received: list[tuple[str, int]] = []
    with _edge(
        tmp_path, caddy, allowlisted=False, upstream_handler=_recording_upstream(received)
    ) as (port, access_log):
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/authorize?client_id=c&state=s")
            response = conn.getresponse()
            response.read()
            assert response.status == 302
            assert "SECRETCODE" in response.getheader("Location", "")  # the client still gets it
        finally:
            conn.close()
        deadline = time.monotonic() + 5
        while not (access_log.exists() and access_log.read_text()) and time.monotonic() < deadline:
            time.sleep(0.05)
    text = access_log.read_text()
    assert text, "no access log line was written"
    assert "SECRETCODE" not in text
    record = json.loads(text.splitlines()[-1])
    assert "Location" not in (record.get("resp_headers") or {})
