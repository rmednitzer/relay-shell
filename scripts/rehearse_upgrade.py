"""Qualify one admitted release-to-current upgrade on an empty disposable hosted VM.

Baseline dependency bytes are a frozen, newly audited fixture, not evidence of a
historical deployment. No secrets or state snapshots are exported. Rollback keeps
post-upgrade audit records and resets grants before the old service restarts.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import http.client
import json
import os
import pwd
import re
import secrets
import shutil
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import rehearse_install as fixture

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests/fixtures/upgrade-v0.3"
ORIGIN = "http://127.0.0.1:8080"
REDIRECT = "http://127.0.0.1:49152/callback"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(directory: Path) -> dict[str, object]:
    data = json.loads((directory / "baseline.json").read_text())
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported baseline manifest")
    for name, pattern in {
        "tag": r"v[0-9]+\.[0-9]+\.[0-9]+",
        "tag_object": r"[a-f0-9]{40}",
        "source_commit": r"[a-f0-9]{40}",
        "version": r"[0-9]+\.[0-9]+\.[0-9]+",
        "mcp_version": r"[0-9]+\.[0-9]+\.[0-9]+",
    }.items():
        if not isinstance(data.get(name), str) or not re.fullmatch(pattern, data[name]):
            raise ValueError("malformed baseline identity")
    if data["tag"] != "v" + data["version"] or data.get("python_minor") != "3.12":
        raise ValueError("unsupported baseline version/profile")
    if digest(directory / "runtime.lock") != data.get("runtime_lock_sha256"):
        raise ValueError("baseline dependency profile changed without review")
    if digest(directory / "runtime.in") != data.get("runtime_input_sha256"):
        raise ValueError("baseline dependency contract changed without review")
    if digest(directory / "advisory-description.txt") != data.get("advisory_description_sha256"):
        raise ValueError("reviewed advisory description changed without review")
    return data


def git(*argv: str) -> str:
    return fixture.checked(["git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *argv]).strip()


def admit(data: dict[str, object], work: Path) -> str:
    tag = str(data["tag"])
    if git("cat-file", "-t", tag) != "tag" or git("rev-parse", tag) != data["tag_object"]:
        raise ValueError("baseline annotated tag identity changed")
    if git("rev-parse", tag + "^{}") != data["source_commit"]:
        raise ValueError("baseline source identity changed")
    git("merge-base", "--is-ancestor", str(data["source_commit"]), "origin/main")
    # Independent protected-main signer material, not the baseline's own key file.
    signers = work / "allowed-signers"
    signers.write_text(git("show", "origin/main:deploy/release-signing.pub") + "\n")
    git("-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={signers}", "verify-tag", tag)
    return digest(signers)


def archive(source: str, destination: Path) -> None:
    destination.mkdir()
    tar = destination.with_suffix(".tar")
    with tar.open("wb") as stream:
        import subprocess

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
    with tarfile.open(tar) as stream:
        stream.extractall(destination, filter="data")


def require_stateless(source: Path) -> None:
    tree = ast.parse(source.read_text())
    function = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_server"), None
    )
    settings = (
        []
        if function is None
        else [
            n.value
            for n in ast.walk(function)
            if isinstance(n, ast.AnnAssign)
            and isinstance(n.target, ast.Name)
            and n.target.id == "fastmcp_kwargs"
            and isinstance(n.value, ast.Dict)
        ]
    )
    if len(settings) != 1:
        raise ValueError("baseline stateless constructor contract changed")
    values = [
        value
        for key, value in zip(settings[0].keys, settings[0].values, strict=True)
        if isinstance(key, ast.Constant) and key.value == "stateless_http"
    ]
    if len(values) != 1 or not isinstance(values[0], ast.Constant) or values[0].value is not True:
        raise ValueError("baseline must explicitly construct a stateless server")


def audit_dispositions(report: Path, directory: Path) -> list[dict[str, str]]:
    if report.stat().st_size > 1_048_576:
        raise ValueError("audit report exceeds byte budget")
    data = json.loads(report.read_text())
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies or data.get("fixes") != []:
        raise ValueError("missing complete read-only dependency audit")

    def normalize(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    expected = {
        (normalize(name), version)
        for name, version in re.findall(
            r"^([A-Za-z0-9_.-]+)==([^\s]+)", (directory / "runtime.lock").read_text(), re.MULTILINE
        )
    }
    reviewed_description = (directory / "advisory-description.txt").read_text()
    observed = set()
    dispositions = []
    for dependency in dependencies:
        name, version = dependency.get("name"), dependency.get("version")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or dependency.get("skip_reason")
            or not isinstance(dependency.get("vulns"), list)
        ):
            raise ValueError("incomplete dependency audit entry")
        key = (normalize(name), version)
        if key in observed:
            raise ValueError("duplicate dependency audit entry")
        observed.add(key)
        for vulnerability in dependency["vulns"]:
            if (
                key != ("mcp", "1.28.1")
                or vulnerability.get("id") not in {"CVE-2026-59951", "GHSA-84m7-p3x7-pcfv"}
                or vulnerability.get("description") != reviewed_description
            ):
                raise ValueError("dependency finding needs a new reviewed disposition")
            dispositions.append(
                {
                    "package": "mcp",
                    "version": "1.28.1",
                    "advisory": "CVE-2026-59951",
                    "disposition": "not affected in this stateless fixture",
                    "basis": (
                        "signed source and live no-session checks; upstream stateless exclusion"
                    ),
                }
            )
    if observed != expected:
        raise ValueError("audit did not cover the exact frozen dependency closure")
    if len(dispositions) != 1:
        raise ValueError("expected exactly one retained reviewed advisory finding")
    return dispositions


def stateless_proof(token: str) -> None:
    for number in (1, 2):
        status, headers, _ = request(
            "POST",
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": number,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "stateless-fixture", "version": "1"},
                },
            },
            token=token,
        )
        if status != 200 or "mcp-session-id" in headers:
            raise RuntimeError("baseline live transport is not the admitted stateless profile")


def request(
    method: str,
    path: str,
    value: dict[str, object] | None = None,
    *,
    form: bool = False,
    token: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=10)
    headers = {"Accept": "application/json, text/event-stream"}
    body = None
    if value is not None:
        headers["Content-Type"] = (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
        body = urlencode(value) if form else json.dumps(value)
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        raw = response.read(1_048_577)
        if len(raw) > 1_048_576:
            raise RuntimeError("fixture response exceeds byte budget")
        return response.status, {k.lower(): v for k, v in response.getheaders()}, raw
    finally:
        connection.close()


def ready() -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            status, _, raw = request("GET", "/.well-known/oauth-authorization-server")
            if status == 200 and json.loads(raw).get("issuer", "").rstrip("/") == ORIGIN:
                return
        except (ConnectionError, OSError):
            pass
        time.sleep(0.25)
    raise RuntimeError("authenticated fixture service did not become ready")


def authorize(client: str, *, bound: bool) -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    params = {
        "client_id": client,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "mcp:tools",
        "state": "synthetic-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if bound:
        params["resource"] = ORIGIN
    status, headers, _ = request("GET", "/authorize?" + urlencode(params))
    location = urlsplit(headers.get("location", ""))
    query = parse_qs(location.query)
    if (
        status not in (302, 303, 307)
        or location.scheme != "http"
        or location.netloc != "127.0.0.1:49152"
        or location.path != "/callback"
        or query.get("state") != ["synthetic-state"]
        or len(query.get("code", [])) != 1
    ):
        raise RuntimeError("fixture authorization did not produce the expected callback")
    return query["code"][0], verifier


def issue(client: str, *, bound: bool) -> dict[str, str]:
    code, verifier = authorize(client, bound=bound)
    params = {
        "grant_type": "authorization_code",
        "client_id": client,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT,
    }
    if bound:
        params["resource"] = ORIGIN
    bad = dict(params, code_verifier="incorrect_fixture_verifier")
    status, _, _ = request("POST", "/token", bad, form=True)
    if status != 400:
        raise RuntimeError("incorrect PKCE verifier was not refused")
    # Use a separate fresh code rather than assume failed-exchange consumption semantics.
    code, verifier = authorize(client, bound=bound)
    params.update(code=code, code_verifier=verifier)
    status, _, raw = request("POST", "/token", params, form=True)
    if status != 200:
        raise RuntimeError("fixture authorization-code exchange failed")
    tokens = json.loads(raw)
    if not tokens.get("access_token") or not tokens.get("refresh_token"):
        raise RuntimeError("fixture token response incomplete")
    return tokens


def refused(token: str | None) -> None:
    status, _, _ = request(
        "POST",
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "upgrade-refusal", "version": "1"},
            },
        },
        token=token,
    )
    if status != 401:
        raise RuntimeError("unadmitted bearer reached MCP")


def records() -> list[dict[str, object]]:
    return [json.loads(line) for line in (fixture.LOG / "audit.jsonl").read_text().splitlines()]


def identity() -> dict[str, str]:
    code = (
        "import importlib.metadata as m,json; "
        "print(json.dumps({n:m.version(n) for n in ['relay-shell','mcp']}))"
    )
    return json.loads(fixture.checked(["sudo", "-u", "relay-shell", fixture.PYTHON, "-c", code]))


def rehearse(output: Path, build_python: str, audit_report: Path) -> None:
    fixture.guard()
    if output.exists():
        raise ValueError("receipt output must be new")
    data = manifest(BASELINE)
    current = git("rev-parse", "HEAD")
    git("diff", "--exit-code", "HEAD")
    with tempfile.TemporaryDirectory(prefix="relay-upgrade-rehearsal-") as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        signer_hash = admit(data, work)
        legacy, target = work / "legacy", work / "target"
        archive(str(data["source_commit"]), legacy)
        archive(current, target)
        require_stateless(legacy / "src/relay_shell/server.py")
        dispositions = audit_dispositions(audit_report, BASELINE)
        # The service UID cannot traverse the runner checkout. Keep the verified
        # public fixture in the disposable work directory instead.
        legacy_lock = work / "legacy-runtime.lock"
        shutil.copyfile(BASELINE / "runtime.lock", legacy_lock)
        legacy_lock.chmod(0o644)
        if digest(legacy_lock) != data["runtime_lock_sha256"]:
            raise RuntimeError("copied baseline dependency profile changed")
        try:
            fixture.checked(
                [
                    "useradd",
                    "--system",
                    "--create-home",
                    "--home-dir",
                    str(fixture.PREFIX),
                    "--shell",
                    "/usr/sbin/nologin",
                    "relay-shell",
                ]
            )
            account = pwd.getpwnam("relay-shell")
            dist = work / "legacy-dist"
            dist.mkdir()
            os.chown(dist, account.pw_uid, account.pw_gid)
            fixture.checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    build_python,
                    "-m",
                    "build",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(dist),
                    str(legacy),
                ]
            )
            wheels = list(dist.glob("*.whl"))
            if len(wheels) != 1:
                raise RuntimeError("expected one baseline wheel")
            legacy_wheel_hash = digest(wheels[0])
            fixture.checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    "/usr/bin/python3",
                    "-m",
                    "venv",
                    str(fixture.PREFIX / "venv"),
                ]
            )
            minor = fixture.checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    fixture.PYTHON,
                    "-c",
                    "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
                ]
            ).strip()
            if minor != data["python_minor"]:
                raise RuntimeError("legacy runtime interpreter profile changed")
            fixture.checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    fixture.PYTHON,
                    "-m",
                    "pip",
                    "install",
                    "--only-binary=:all:",
                    "--require-hashes",
                    "-r",
                    str(legacy_lock),
                ]
            )
            fixture.checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    fixture.PYTHON,
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    str(wheels[0]),
                ]
            )
            fixture.checked(["sudo", "-u", "relay-shell", fixture.PYTHON, "-m", "pip", "check"])
            if identity() != {"relay-shell": data["version"], "mcp": data["mcp_version"]}:
                raise RuntimeError("baseline installation identity mismatch")
            fixture.CONFIG.mkdir(mode=0o750)
            os.chown(fixture.CONFIG, 0, account.pw_gid)
            env_file = fixture.CONFIG / "relay-shell.env"
            env_file.write_text(
                "RELAY_SHELL_TRANSPORT=http\nRELAY_SHELL_HTTP_HOST=127.0.0.1\n"
                "RELAY_SHELL_HTTP_PORT=8080\nRELAY_SHELL_AUTH_ENABLED=true\n"
                f"RELAY_SHELL_AUTH_ISSUER={ORIGIN}\nRELAY_SHELL_AUDIT_CHAIN=true\n"
                "RELAY_SHELL_POLICY_MODE=open\n"
            )
            env_file.chmod(0o640)
            os.chown(env_file, 0, account.pw_gid)
            fixture.LOG.mkdir()
            os.chown(fixture.LOG, account.pw_uid, account.pw_gid)
            audit = fixture.LOG / "audit.jsonl"
            audit.touch(mode=0o600)
            os.chown(audit, account.pw_uid, account.pw_gid)
            fixture.DROPIN.mkdir()
            for source, destination in [
                ("systemd/relay-shell.service", fixture.UNIT),
                ("systemd/relay-shell.service.d/hardening.conf", fixture.DROPIN / "hardening.conf"),
                ("logrotate/relay-shell", fixture.ROTATE),
            ]:
                fixture.checked(
                    ["install", "-m", "0644", str(legacy / "deploy" / source), str(destination)]
                )
            fixture.checked(["systemctl", "daemon-reload"])
            fixture.service(True)
            ready()
            status, _, raw = request(
                "POST",
                "/register",
                {
                    "client_name": "Synthetic cross-version fixture",
                    "redirect_uris": [REDIRECT],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            if status not in (200, 201):
                raise RuntimeError("baseline public-client registration failed")
            client = json.loads(raw)["client_id"]
            old_tokens = issue(client, bound=False)
            refused(None)
            stateless_proof(old_tokens["access_token"])
            fixture.mcp_proof(token=old_tokens["access_token"])
            fixture.service(False)
            state = fixture.PREFIX / "oauth"
            raw_store = (state / "tokens.json").read_text()
            if any(
                secret not in raw_store
                for secret in (old_tokens["access_token"], old_tokens["refresh_token"])
            ):
                raise RuntimeError("baseline did not exercise raw-token storage")
            old_records = records()
            if not old_records:
                raise RuntimeError("baseline audit proof missing")
            before = {str(path): fixture.inventory(path) for path in fixture.TARGETS}
            snapshot = work / "baseline-snapshot"
            snapshot.mkdir(mode=0o700)
            for index, path in enumerate(fixture.TARGETS):
                fixture.checked(["cp", "-a", str(path), str(snapshot / str(index))])
            fixture.checked(["bash", str(target / "deploy/install.sh")])
            fixture.checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    fixture.PYTHON,
                    str(target / "scripts/reconcile_runtime.py"),
                    str(target / "requirements/runtime-py3.12.txt"),
                    str(target / "pyproject.toml"),
                ]
            )
            target_identity = identity()
            expected_version = tomllib.loads((target / "pyproject.toml").read_text())["project"][
                "version"
            ]
            target_lock = (target / "requirements/runtime-py3.12.txt").read_text()
            sdk = re.search(r"^mcp==([^\s]+)", target_lock, re.MULTILINE)
            if sdk is None or target_identity != {"relay-shell": expected_version, "mcp": sdk[1]}:
                raise RuntimeError("target identity differs from source and locked SDK")
            if expected_version == data["version"] or sdk[1] == data["mcp_version"]:
                raise RuntimeError("upgrade did not cross application and SDK versions")
            if fixture.inventory(fixture.CONFIG) != before[str(fixture.CONFIG)]:
                raise RuntimeError("upgrade changed operator configuration")
            fixture.service(True)
            ready()
            refused(old_tokens["access_token"])
            status, _, _ = request(
                "POST",
                "/token",
                {
                    "grant_type": "refresh_token",
                    "client_id": client,
                    "refresh_token": old_tokens["refresh_token"],
                    "resource": ORIGIN,
                },
                form=True,
            )
            if status != 400:
                raise RuntimeError("unbound legacy refresh grant was not refused")
            migrated = json.loads((state / "tokens.json").read_text())
            if any(not key.startswith(("sha256:", "refresh:sha256:")) for key in migrated):
                raise RuntimeError("legacy token keys were not hashed")
            if any(
                secret in json.dumps(migrated)
                for secret in (old_tokens["access_token"], old_tokens["refresh_token"])
            ):
                raise RuntimeError("raw legacy secrets remain after migration")
            approvals = json.loads((state / "approvals.json").read_text())
            if approvals.get(client, {}).get("approved") is not True:
                raise RuntimeError("existing client approval was not carried forward")
            current_tokens = issue(client, bound=True)
            fixture.mcp_proof(token=current_tokens["access_token"])
            renewal = {
                "grant_type": "refresh_token",
                "client_id": client,
                "refresh_token": current_tokens["refresh_token"],
                "resource": ORIGIN,
            }
            status, _, _ = request(
                "POST", "/token", dict(renewal, resource=ORIGIN + "/other"), form=True
            )
            if status != 400:
                raise RuntimeError("wrong-resource renewal was not refused")
            status, _, raw = request("POST", "/token", renewal, form=True)
            if status != 200:
                raise RuntimeError("current refresh rotation failed")
            rotated = json.loads(raw)
            if rotated.get("refresh_token") in (None, current_tokens["refresh_token"]):
                raise RuntimeError("refresh token did not rotate")
            status, _, _ = request("POST", "/token", renewal, form=True)
            if status != 400:
                raise RuntimeError("spent refresh token was accepted")
            fixture.mcp_proof(token=rotated["access_token"])
            for key in ("access_token", "refresh_token"):
                status, _, _ = request(
                    "POST",
                    "/revoke",
                    # SDK revocation model requires this nullable field even for
                    # a public client; empty form text carries no credential.
                    {
                        "client_id": client,
                        "client_secret": "",
                        "token": rotated[key],
                        "token_type_hint": key,
                    },
                    form=True,
                )
                if status != 200:
                    raise RuntimeError("current token revocation failed")
            refused(rotated["access_token"])
            status, _, _ = request(
                "POST", "/token", dict(renewal, refresh_token=rotated["refresh_token"]), form=True
            )
            if status != 400:
                raise RuntimeError("revoked refresh token was accepted")
            fixture.service(False)
            latest_records = records()
            if latest_records[: len(old_records)] != old_records or len(latest_records) <= len(
                old_records
            ):
                raise RuntimeError("upgrade did not preserve and extend baseline audit history")
            tail = work / "accepted-audit"
            fixture.checked(["cp", "-a", str(fixture.LOG), str(tail)])
            tail_hash = digest(tail / "audit.jsonl")
            fixture.run(["chattr", "-a", str(fixture.LOG / "audit.jsonl")])
            for index, path in enumerate(fixture.TARGETS):
                shutil.rmtree(path) if path.is_dir() else path.unlink()
                fixture.checked(["cp", "-a", str(snapshot / str(index)), str(path)])
                if fixture.inventory(path) != before[str(path)]:
                    raise RuntimeError("consistent baseline snapshot restoration changed identity")
            # Do not discard accepted audit records or revive backed-up grants.
            shutil.rmtree(fixture.LOG)
            fixture.checked(["cp", "-a", str(tail), str(fixture.LOG)])
            if digest(fixture.LOG / "audit.jsonl") != tail_hash:
                raise RuntimeError("accepted post-snapshot audit records were lost")
            reset = (
                "from relay_shell.auth.oauth import FileOAuthProvider; "
                "p=FileOAuthProvider('/var/lib/relay-shell/oauth',single_client=True,"
                "access_ttl=3600,refresh_ttl=3600,code_ttl=300); "
                "p._tokens.save({}); p._codes.save({})"
            )
            fixture.checked(["sudo", "-u", "relay-shell", fixture.PYTHON, "-c", reset])
            if identity() != {"relay-shell": data["version"], "mcp": data["mcp_version"]}:
                raise RuntimeError("rollback restored the wrong runtime")
            fixture.checked(["sudo", "-u", "relay-shell", fixture.PYTHON, "-m", "pip", "check"])
            fixture.checked(["systemctl", "daemon-reload"])
            fixture.service(True)
            ready()
            for token in (
                old_tokens["access_token"],
                current_tokens["access_token"],
                rotated["access_token"],
            ):
                refused(token)
            for old in (old_tokens, current_tokens):
                status, _, _ = request(
                    "POST",
                    "/token",
                    {
                        "grant_type": "refresh_token",
                        "client_id": client,
                        "refresh_token": old["refresh_token"],
                    },
                    form=True,
                )
                if status != 400:
                    raise RuntimeError("rollback revived a retained refresh grant")
            restored = issue(client, bound=False)
            stateless_proof(restored["access_token"])
            fixture.mcp_proof(token=restored["access_token"])
            fixture.service(False)
            final_records = records()
            if final_records[: len(latest_records)] != latest_records or len(final_records) <= len(
                latest_records
            ):
                raise RuntimeError("rolled-back runtime did not extend retained audit history")
            fixture.checked(
                [
                    "sudo",
                    "-u",
                    "relay-shell",
                    str(fixture.PREFIX / "venv/bin/relay-shell"),
                    "--verify-audit",
                    "--audit-path",
                    str(fixture.LOG / "audit.jsonl"),
                    "--json",
                ]
            )
            output.mkdir(mode=0o755)
            receipt = {
                "source_commit": current,
                "baseline_tag": data["tag"],
                "baseline_tag_object": data["tag_object"],
                "baseline_source": data["source_commit"],
                "protected_main_signer_file_sha256": signer_hash,
                "legacy_wheel_sha256": legacy_wheel_hash,
                "legacy_runtime_lock_sha256": data["runtime_lock_sha256"],
                "legacy_advisory_dispositions": dispositions,
                "legacy_stateless_source_and_live_checks": "passed",
                "target_installer_sha256": digest(target / "deploy/install.sh"),
                "target_runtime_lock_sha256": digest(target / "requirements/runtime-py3.12.txt"),
                "baseline_identity": {"relay-shell": data["version"], "mcp": data["mcp_version"]},
                "target_identity": target_identity,
                "python_minor": minor,
                "target_complete_distribution_inventory": "passed",
                "upgrade_raw_token_hash_migration": "passed",
                "legacy_unbound_grants_refused": "passed",
                "existing_client_approval_preserved": "passed",
                "pkce_bad_verifier_refused": "passed",
                "target_reauthorization_rotation_revocation": "passed",
                "consistent_snapshot_restoration": "passed",
                "rollback_grants_reset_before_restart": "passed",
                "rollback_authenticated_mcp": "passed",
                "audit_history_continued_across_both_versions": "passed",
                "retained_upgrade_audit_sha256": tail_hash,
                "scope": (
                    "one admitted v0.3.0 fixture to current source on Ubuntu 24.04/Python 3.12; "
                    "loopback HTTP; snapshot rollback with grant reset and retained audit; "
                    "no live host, TLS, arbitrary versions, binary-only downgrade "
                    "or automatic rollback"
                ),
            }
            (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps(receipt))
        except BaseException:
            print(fixture.run(["journalctl", "-u", "relay-shell", "-n", "30", "--no-pager"]).stdout)
            raise
        finally:
            fixture.run(["systemctl", "stop", "relay-shell"])
            fixture.run(["chattr", "-a", str(fixture.LOG / "audit.jsonl")])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-python", required=True)
    parser.add_argument("--audit-report", type=Path, required=True)
    arguments = parser.parse_args()
    rehearse(arguments.output.resolve(), arguments.build_python, arguments.audit_report.resolve())
