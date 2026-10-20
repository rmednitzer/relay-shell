"""Destructive installer qualification for an empty GitHub-hosted disposable VM only.

Never run on an operational host. Snapshots contain synthetic fixture state only;
only a source-bound JSON receipt is exported. Production install.sh is unmodified.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = Path("/var/lib/relay-shell")
CONFIG = Path("/etc/relay-shell")
LOG = Path("/var/log/relay-shell")
UNIT = Path("/etc/systemd/system/relay-shell.service")
DROPIN = Path("/etc/systemd/system/relay-shell.service.d")
ROTATE = Path("/etc/logrotate.d/relay-shell")
TARGETS = (PREFIX, CONFIG, LOG, UNIT, DROPIN, ROTATE)
PYTHON = str(PREFIX / "venv/bin/python")


def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, timeout=600, **kwargs)


def checked(argv: list[str], **kwargs: object) -> str:
    result = run(argv, **kwargs)
    if result.returncode:
        # Bounded diagnostics; fixtures contain no operational configuration.
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout


def guard() -> None:
    if (
        os.geteuid() != 0
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise RuntimeError("requires root on an explicitly disposable GitHub-hosted runner")
    if any(path.exists() or path.is_symlink() for path in TARGETS):
        raise RuntimeError("refusing a host with pre-existing relay-shell paths")
    try:
        pwd.getpwnam("relay-shell")
    except KeyError:
        pass
    else:
        raise RuntimeError("refusing a pre-existing relay-shell account")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 8080))
    if not Path("/run/systemd/system").is_dir():
        raise RuntimeError("requires systemd, not a simulated systemctl")


def inventory(path: Path) -> dict[str, object]:
    entries = [path, *sorted(path.rglob("*"))] if path.is_dir() else [path]
    result = {}
    for item in entries:
        info = item.lstat()
        content = (
            "link:" + str(item.readlink())
            if item.is_symlink()
            else hashlib.sha256(item.read_bytes()).hexdigest()
            if item.is_file()
            else "dir"
        )
        result[str(item.relative_to(path))] = [
            stat.S_IMODE(info.st_mode),
            info.st_uid,
            info.st_gid,
            content,
        ]
    return result


def service(active: bool) -> None:
    checked(["systemctl", "start" if active else "stop", "relay-shell"])


def mcp_proof() -> None:
    session = None

    def request(body: dict[str, object]) -> dict[str, object]:
        nonlocal session
        connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=10)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if session:
            headers["Mcp-Session-Id"] = session
        try:
            connection.request("POST", "/mcp", json.dumps(body), headers)
            response = connection.getresponse()
            session = response.getheader("Mcp-Session-Id") or session
            data = response.read(1_048_577)
            if response.status not in (200, 202) or len(data) > 1_048_576:
                raise RuntimeError("bounded MCP request failed")
            if not data:
                return {}
            if response.getheader("Content-Type", "").startswith("text/event-stream"):
                data = next(line[6:] for line in data.splitlines() if line.startswith(b"data: "))
            result = json.loads(data)
            if "error" in result:
                raise RuntimeError("MCP returned a protocol error")
            return result
        finally:
            connection.close()

    for _ in range(60):
        try:
            response = request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "installer-rehearsal", "version": "1"},
                    },
                }
            )
            if "serverInfo" not in response.get("result", {}):
                raise RuntimeError("MCP initialization lacks server identity")
            break
        except (ConnectionError, OSError):
            time.sleep(0.25)
    else:
        raise RuntimeError("installed service never became ready")
    request({"jsonrpc": "2.0", "method": "notifications/initialized"})
    result = request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "shell_exec", "arguments": {"command": "printf 'installer-proof'"}},
        }
    )
    if "installer-proof" not in json.dumps(result) or result.get("result", {}).get("isError"):
        raise RuntimeError("installed MCP shell execution failed")


def oauth_proof() -> None:
    code = """import asyncio
from relay_shell.auth.oauth import FileOAuthProvider
p = FileOAuthProvider('/var/lib/relay-shell/oauth', single_client=True, access_ttl=3600,
                      refresh_ttl=3600, code_ttl=300)
t = asyncio.run(p.load_access_token('synthetic_recovery_token'))
if t is None or t.client_id != 'synthetic-client':
    raise SystemExit('restored synthetic OAuth token was not recognized')
"""
    checked(["sudo", "-u", "relay-shell", PYTHON, "-c", code])


def rehearse(output: Path) -> None:
    guard()
    if output.exists():
        raise RuntimeError("output must be new")
    source = checked(
        ["git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), "rev-parse", "HEAD"]
    ).strip()
    with tempfile.TemporaryDirectory(prefix="relay-install-rehearsal-") as directory:
        work = Path(directory)
        work.chmod(0o755)
        source_tree = work / "source"
        source_tree.mkdir()
        archive = work / "source.tar"
        with archive.open("wb") as stream:
            subprocess.run(
                [
                    "git",
                    "-c",
                    f"safe.directory={ROOT}",
                    "-C",
                    str(ROOT),
                    "archive",
                    "--format=tar",
                    source,
                ],
                stdout=stream,
                check=True,
                timeout=30,
            )
        with tarfile.open(archive) as stream:
            stream.extractall(source_tree, filter="data")
        installer = ["bash", str(source_tree / "deploy/install.sh")]
        try:
            checked(installer)
            if run(["systemctl", "is-active", "--quiet", "relay-shell"]).returncode == 0:
                raise RuntimeError("installer unexpectedly started the service")
            if run(["systemctl", "is-enabled", "--quiet", "relay-shell"]).returncode == 0:
                raise RuntimeError("installer unexpectedly enabled the service")
            env_file = CONFIG / "relay-shell.env"
            with env_file.open("a") as stream:
                stream.write("\n# synthetic recovery fixture\nRELAY_SHELL_AUDIT_CHAIN=true\n")
            with UNIT.open("a") as stream:
                stream.write("\n# synthetic operator customization\n")
            account = pwd.getpwnam("relay-shell")
            state = PREFIX / "oauth"
            state.mkdir(mode=0o700)
            token = hashlib.sha256(b"synthetic_recovery_token").hexdigest()
            for name, value in {
                "clients.json": {},
                "approvals.json": {},
                "codes.json": {},
                "tokens.json": {
                    "sha256:" + token: {
                        "client_id": "synthetic-client",
                        "scopes": ["mcp:tools"],
                        "expires_at": int(time.time()) + 3600,
                        "resource": "https://localhost:8080",
                    }
                },
            }.items():
                path = state / name
                path.write_text(json.dumps(value))
                path.chmod(0o600)
                os.chown(path, account.pw_uid, account.pw_gid)
            os.chown(state, account.pw_uid, account.pw_gid)
            ssh = PREFIX / ".ssh"
            ssh.mkdir(mode=0o700)
            checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / "key")])
            trust = ssh / "known_hosts"
            trust.write_text("fixture.invalid " + (work / "key.pub").read_text())
            trust.chmod(0o600)
            for path in (ssh, trust):
                os.chown(path, account.pw_uid, account.pw_gid)
            checked(["systemctl", "daemon-reload"])
            oauth_proof()
            service(True)
            mcp_proof()
            service(False)
            attributes = run(["lsattr", "-d", str(LOG / "audit.jsonl")])
            append_only = attributes.returncode == 0 and "a" in attributes.stdout.split()[0]
            before = {str(path): inventory(path) for path in TARGETS}
            snapshot = work / "snapshot"
            snapshot.mkdir(mode=0o700)
            for index, path in enumerate(TARGETS):
                checked(["cp", "-a", str(path), str(snapshot / str(index))])
            # Actual repeat installer: preserve env/OAuth/audit, back up edited unit.
            checked(installer)
            for path in (CONFIG, LOG, PREFIX / "oauth", PREFIX / ".ssh"):
                expected = (
                    before[str(path)]
                    if str(path) in before
                    else inventory(snapshot / "0" / path.relative_to(PREFIX))
                )
                if inventory(path) != expected:
                    raise RuntimeError("repeat installer changed retained state")
            if not list((PREFIX / "preinstall-backups").iterdir()):
                raise RuntimeError("edited unit was not backed up")
            # Inject partial dependency replacement at the actual runtime pip boundary.
            shim = work / "shim"
            shim.mkdir()
            sudo = shim / "sudo"
            sudo.write_text(
                '''#!/bin/bash
target=/var/lib/relay-shell/venv/bin/python
if [[ "$*" == "-u relay-shell $target -m pip install --quiet --only-binary"* ]]; then
    /usr/bin/sudo -u relay-shell "$target" -m pip uninstall -y mcp >/dev/null
    touch "'''
                + str(work / "injected")
                + """"
    kill -TERM "$PPID"
    exit 143
fi
exec /usr/bin/sudo "$@"
"""
            )
            sudo.chmod(0o755)
            failed = run(installer, env={**os.environ, "PATH": f"{shim}:/usr/bin:/bin"})
            if failed.returncode == 0 or not (work / "injected").exists():
                raise RuntimeError("intended installer interruption was not reached")
            if run(["sudo", "-u", "relay-shell", PYTHON, "-m", "pip", "check"]).returncode == 0:
                raise RuntimeError("partial-runtime fault was not detected")
            service(False)
            run(["chattr", "-a", str(LOG / "audit.jsonl")])
            for index, path in enumerate(TARGETS):
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                checked(["cp", "-a", str(snapshot / str(index)), str(path)])
                if inventory(path) != before[str(path)]:
                    raise RuntimeError("restore changed content, modes, owner or symlinks")
            if append_only:
                checked(["chattr", "+a", str(LOG / "audit.jsonl")])
            checked(["systemctl", "daemon-reload"])
            checked(["sudo", "-u", "relay-shell", PYTHON, "-m", "pip", "check"])
            oauth_proof()
            old_records = [
                json.loads(line) for line in (LOG / "audit.jsonl").read_text().splitlines()
            ]
            if not old_records or "chain" not in old_records[-1]:
                raise RuntimeError("snapshot lacked chained execution evidence")
            service(True)
            mcp_proof()
            service(False)
            checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    str(PREFIX / "venv/bin/relay-shell"),
                    "--verify-audit",
                    "--audit-path",
                    str(LOG / "audit.jsonl"),
                    "--json",
                ]
            )
            records = [json.loads(line) for line in (LOG / "audit.jsonl").read_text().splitlines()]
            if records[: len(old_records)] != old_records or len(records) <= len(old_records):
                raise RuntimeError("restored service did not extend retained audit history")
            output.mkdir(mode=0o755)
            receipt = {
                "source_commit": source,
                "installer_sha256": hashlib.sha256(
                    (source_tree / "deploy/install.sh").read_bytes()
                ).hexdigest(),
                "python": checked(["sudo", "-u", "relay-shell", PYTHON, "-V"]).strip(),
                "fresh_install": "passed",
                "repeat_upgrade_state_preservation": "passed",
                "partial_runtime_interruption_detected": True,
                "restored_content_modes_owners_symlinks_identical": True,
                "append_only_restored_where_supported": append_only,
                "restored_dependency_check": "passed",
                "restored_oauth_token_load": "passed",
                "restored_mcp_shell_call": "passed",
                "restored_audit_chain_continuity": "passed",
                "scope": (
                    "empty disposable hosted VM; synthetic state; no live deployment, "
                    "real OAuth flow, edge TLS, off-host audit, full-host disaster "
                    "recovery or atomic installer rollback"
                ),
            }
            (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps(receipt))
        finally:
            run(["systemctl", "stop", "relay-shell"])
            run(["chattr", "-a", str(LOG / "audit.jsonl")])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    rehearse(arguments.output.resolve())
