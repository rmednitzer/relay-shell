#!/usr/bin/env python3
"""Explicit offline migration of native opaque grants; dry-run unless --apply.

This records a new operator-approved binding, not evidence of a lost old audience.
Existing explicit foreign bindings are never changed; expiry/scopes are preserved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from relay_shell.auth.resource import normalize_resource


def bind_records(
    tokens: dict[str, Any], clients: dict[str, Any], resource: str, now: int
) -> tuple[dict[str, Any], dict[str, int]]:
    resource = normalize_resource(resource)
    result = json.loads(json.dumps(tokens))
    counts = {"bound_access": 0, "bound_refresh": 0, "expired": 0, "already_bound": 0}
    for key, record in result.items():
        if not isinstance(record, dict) or type(record.get("expires_at")) is not int:
            raise ValueError("Malformed opaque grant; migration refused")
        if record["expires_at"] <= now:
            counts["expired"] += 1
            continue
        native_token = key.removeprefix("refresh:")
        if (
            not native_token
            or record.get("token") != native_token
            or record.get("client_id") not in clients
            or record.get("scopes") != ["mcp:tools"]
        ):
            raise ValueError("Grant origin, registration or scope cannot be established")
        if record.get("resource") is not None:
            if normalize_resource(record["resource"]) != resource:
                raise ValueError("Explicit foreign resource; migration refused")
            counts["already_bound"] += 1
            continue
        record["resource"] = resource
        counts["bound_refresh" if key.startswith("refresh:") else "bound_access"] += 1
    return result, counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--backup-dir", type=Path)
    args = parser.parse_args()
    path = args.state_dir / "tokens.json"
    for item in (args.state_dir, path, args.state_dir / "clients.json"):
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SystemExit("Refusing symlink or non-private OAuth state")
    original = path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    clients = json.loads((args.state_dir / "clients.json").read_text())
    result, counts = bind_records(json.loads(original), clients, args.resource, int(time.time()))
    if args.apply:
        if os.geteuid() != 0 or not args.backup_dir or args.expected_sha256 != digest:
            raise SystemExit(
                "Apply requires root, private backup directory and exact preimage hash"
            )
        active = subprocess.check_output(
            ["systemctl", "show", "relay-shell.service", "-p", "ActiveState", "--value"], text=True
        ).strip()
        pid = subprocess.check_output(
            ["systemctl", "show", "relay-shell.service", "-p", "MainPID", "--value"], text=True
        ).strip()
        if active not in ("inactive", "failed") or pid != "0":
            raise SystemExit("Stop relay-shell.service before applying the migration")
        args.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.backup_dir.is_symlink() or args.backup_dir.stat().st_mode & 0o077:
            raise SystemExit("Backup directory is not private")
        backup = args.backup_dir / ("tokens-" + digest + ".before.json")
        backup_fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(backup_fd, "wb") as output:
            output.write(original)
            output.flush()
            os.fsync(output.fileno())
        metadata = path.stat()
        fd, temporary = tempfile.mkstemp(prefix=".tokens-resource-", dir=args.state_dir)
        try:
            with os.fdopen(fd, "w") as output:
                os.fchmod(output.fileno(), stat.S_IMODE(metadata.st_mode))
                os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
                json.dump(result, output, indent=2)
                output.flush()
                os.fsync(output.fileno())
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("OAuth state changed concurrently; refusing overwrite")
            Path(temporary).replace(path)
            directory = os.open(args.state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)
    print(json.dumps({"applied": args.apply, "preimage_sha256": digest, "counts": counts}))


if __name__ == "__main__":
    main()
