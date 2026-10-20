"""Root-private installer transaction custody and explicit interrupted recovery.

Run only through deploy/install.sh while its exclusive lock is held and the
service remains stopped. The fixed target set excludes mutable auth/audit/SSH.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path("/var/backups/relay-shell-installer")
PENDING = ROOT / "pending.json"
TARGETS = (
    Path("/var/lib/relay-shell/venv"),
    Path("/etc/relay-shell"),
    Path("/etc/systemd/system/relay-shell.service"),
    Path("/etc/systemd/system/relay-shell.service.d"),
    Path("/etc/logrotate.d/relay-shell"),
)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(path: Path) -> dict[str, list[Any]] | None:
    if not path.exists() and not path.is_symlink():
        return None
    result: dict[str, list[Any]] = {}

    def visit(item: Path, relative: str) -> None:
        if len(result) >= 100_000:
            raise ValueError("snapshot entry bound exceeded")
        info = item.lstat()
        metadata: list[Any] = [stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid]
        if stat.S_ISLNK(info.st_mode):
            result[relative] = [*metadata, "link", os.readlink(item)]  # noqa: PTH115 — preserve raw link text
        elif stat.S_ISREG(info.st_mode):
            result[relative] = [*metadata, "file", digest(item)]
        elif stat.S_ISDIR(info.st_mode):
            result[relative] = [*metadata, "directory"]
            for child in sorted(item.iterdir()):
                visit(child, child.name if relative == "." else relative + "/" + child.name)
        else:
            raise ValueError("unsupported snapshot entry type")

    visit(path, ".")
    return result


def private_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("transaction directory must be root-owned and private")


def transaction_path(name: str) -> Path:
    if not re.fullmatch(r"install-[A-Za-z0-9]{8}", name):
        raise ValueError("invalid transaction identity")
    path = ROOT / name
    private_directory(path)
    return path


def read_json(path: Path, bound: int) -> Any:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size > bound:
        raise ValueError("invalid transaction metadata file")
    return json.loads(path.read_text())


def atomic_json(path: Path, value: Any) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".transaction-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def synchronize() -> None:
    # Flush each filesystem containing managed state before clearing the record.
    for path in (ROOT, Path("/var/lib/relay-shell"), Path("/etc")):
        subprocess.run(["/usr/bin/sync", "-f", str(path)], check=True, timeout=120)


def begin(path: Path) -> None:
    if path.parent != ROOT or transaction_path(path.name) != path:
        raise ValueError("transaction escaped recovery root")
    if PENDING.exists() or PENDING.is_symlink():
        raise ValueError("an unfinished installation already exists")
    expected_mapping = "".join(str(target) + "\n" for target in TARGETS)
    if (path / "targets.txt").read_text() != expected_mapping:
        raise ValueError("snapshot target mapping differs from installer contract")
    snapshots = []
    for index, target in enumerate(TARGETS):
        saved = inventory(path / str(index))
        if saved != inventory(target):
            raise ValueError("snapshot differs from original target")
        snapshots.append(saved)
    atomic_json(path / "manifest.json", {"schema": 1, "snapshots": snapshots})
    subprocess.run(["/usr/bin/sync", "-f", str(path)], check=True, timeout=120)
    atomic_json(
        PENDING, {"transaction": path.name, "manifest_sha256": digest(path / "manifest.json")}
    )


def pending() -> tuple[Path, list[Any]]:
    record = read_json(PENDING, 1024)
    if not isinstance(record, dict) or set(record) != {"transaction", "manifest_sha256"}:
        raise ValueError("malformed pending record")
    name = record["transaction"]
    if not isinstance(name, str):
        raise ValueError("malformed pending identity")
    path = transaction_path(name)
    manifest = read_json(path / "manifest.json", 32 * 1024 * 1024)
    if digest(path / "manifest.json") != record["manifest_sha256"]:
        raise ValueError("snapshot manifest integrity changed")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "snapshots"}
        or type(manifest.get("schema")) is not int
        or manifest["schema"] != 1
    ):
        raise ValueError("unsupported transaction manifest")
    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != len(TARGETS):
        raise ValueError("incomplete transaction manifest")
    for index, saved in enumerate(snapshots):
        if inventory(path / str(index)) != saved:
            raise ValueError("sealed snapshot integrity changed")
    return path, snapshots


def restore() -> None:
    path, snapshots = pending()  # Validate all evidence before removing any target.
    for index, target in enumerate(TARGETS):
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            target.unlink()
        elif target.exists():
            shutil.rmtree(target)
        if snapshots[index] is not None:
            subprocess.run(
                ["/usr/bin/cp", "-a", "--", str(path / str(index)), str(target)], check=True
            )
    verify_restored(snapshots)


def verify_restored(snapshots: list[Any]) -> None:
    if any(inventory(target) != saved for target, saved in zip(TARGETS, snapshots, strict=True)):
        raise ValueError("restored target inventory differs from sealed snapshot")


def complete(*, restored: bool) -> None:
    _, snapshots = pending()
    if restored:
        verify_restored(snapshots)
    synchronize()
    PENDING.unlink()
    sync_directory(ROOT)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["begin", "restore", "complete", "complete-restoration"])
    parser.add_argument("snapshot", type=Path, nargs="?")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required")
    private_directory(ROOT)
    if args.command == "begin":
        if args.snapshot is None:
            parser.error("snapshot path required")
        begin(args.snapshot)
    elif args.snapshot is not None:
        parser.error("unexpected snapshot path")
    elif args.command == "restore":
        restore()
    else:
        complete(restored=args.command == "complete-restoration")
