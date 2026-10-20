"""Recovery evidence rejects changed contents, links, ownership and identities."""

from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "installer_transaction",
    Path(__file__).resolve().parents[1] / "scripts/installer_transaction.py",
)
assert SPEC is not None and SPEC.loader is not None
transaction = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transaction)


def test_snapshot_inventory_preserves_raw_links_and_rejects_changes(tmp_path: Path) -> None:
    file = tmp_path / "data"
    file.write_text("synthetic")
    file.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to("./data")
    before = transaction.inventory(tmp_path)
    assert before["link"][-1] == "./data"
    link.unlink()
    link.symlink_to("data")
    assert transaction.inventory(tmp_path) != before
    link.unlink()
    link.symlink_to("./data")
    file.chmod(0o644)
    assert transaction.inventory(tmp_path) != before
    file.chmod(0o600)
    file.write_text("changed")
    assert transaction.inventory(tmp_path) != before
    assert transaction.inventory(tmp_path / "absent") is None


@pytest.mark.parametrize(
    "name", ["../install-abcdefgh", "/tmp/install-abcdefgh", "install-x", "install-abcdefgh/child"]
)
def test_recovery_identity_cannot_escape_custody(name: str) -> None:
    with pytest.raises(ValueError, match="identity"):
        transaction.transaction_path(name)


def test_transaction_directory_rejects_wrong_owner_mode_and_symlink() -> None:
    info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
    path = SimpleNamespace(lstat=lambda: info)
    transaction.private_directory(path)
    for mode, uid in [
        (stat.S_IFDIR | 0o700, 999),
        (stat.S_IFDIR | 0o755, 0),
        (stat.S_IFLNK | 0o700, 0),
    ]:
        info.st_mode, info.st_uid = mode, uid
        with pytest.raises(ValueError, match="root-owned and private"):
            transaction.private_directory(path)


def test_metadata_reader_rejects_nonregular_unowned_and_oversized_files() -> None:
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_size=2)
    path = SimpleNamespace(lstat=lambda: info, read_text=lambda: "{}")
    assert transaction.read_json(path, 1024) == {}
    for mode, uid, size in [
        (stat.S_IFLNK | 0o600, 0, 2),
        (stat.S_IFREG | 0o600, 999, 2),
        (stat.S_IFREG | 0o600, 0, 1025),
    ]:
        info.st_mode, info.st_uid, info.st_size = mode, uid, size
        with pytest.raises(ValueError, match="metadata"):
            transaction.read_json(path, 1024)


def test_manifest_binds_ordered_target_paths_and_schema() -> None:
    paths = [str(path) for path in transaction.TARGETS]
    snapshots = [None] * len(paths)
    manifest = {"schema": 1, "targets": paths, "snapshots": snapshots}
    assert transaction.validate_manifest(manifest) == snapshots
    for changed in [list(reversed(paths)), ["/different", *paths[1:]]]:
        with pytest.raises(ValueError, match="target mapping"):
            transaction.validate_manifest(dict(manifest, targets=changed))
    with pytest.raises(ValueError, match="schema"):
        transaction.validate_manifest(dict(manifest, schema=True))
    with pytest.raises(ValueError, match="incomplete"):
        transaction.validate_manifest(dict(manifest, snapshots=snapshots[:-1]))


def test_atomic_writer_rejects_oversize_before_publishing(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    value = {"synthetic": "é"}
    size = len((json.dumps(value, sort_keys=True) + "\n").encode())
    with pytest.raises(ValueError, match="reader bound"):
        transaction.atomic_json(path, value, bound=size - 1)
    assert not path.exists()
    assert not list(tmp_path.iterdir())
    transaction.atomic_json(path, value, bound=size)
    before = path.read_bytes()
    assert len(before) == size and json.loads(before) == value
    with pytest.raises(ValueError, match="reader bound"):
        transaction.atomic_json(path, {"synthetic": "longer" * 10}, bound=size)
    assert path.read_bytes() == before
