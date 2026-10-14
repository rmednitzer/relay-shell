"""A14-D15: the logrotate config keeps archives append-only without stalling the rotation.

`logrotate` compresses the previous archive (`delaycompress`) before it runs `prerotate`, and
it unlinks archives past `rotate N`. On a file with ``chattr +a`` both fail, and a failed
compress aborts the rotation. The config therefore drops the attribute in `firstaction`,
restores it on the new active file in `postrotate` and on every archive in `lastaction`.

The behavioural test needs a real ``logrotate`` and a filesystem and privilege that accept
``chattr +a`` (root on ext4/xfs/overlayfs), so it skips elsewhere, including most CI runners;
the text test below runs everywhere.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

CONFIG = Path(__file__).resolve().parent.parent / "deploy" / "logrotate" / "relay-shell"


def _block(text: str, name: str) -> str:
    match = re.search(rf"^\s*{name}\n(.*?)^\s*endscript", text, re.S | re.M)
    assert match, f"{name} script missing"
    return match.group(1)


def test_attribute_handling_covers_the_archives_in_the_right_hooks() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "prerotate" not in code, "prerotate runs after the delayed compress; use firstaction"
    first, post, last = (_block(text, n) for n in ("firstaction", "postrotate", "lastaction"))
    assert "chattr -a /var/log/relay-shell/audit.jsonl " in first
    assert "audit.jsonl-*" in first and "chattr -a" in first
    assert "chattr +a /var/log/relay-shell/audit.jsonl " in post
    assert "audit.jsonl-*" in last and "chattr +a" in last
    assert "delaycompress" in text  # the writer may still hold the old file for a moment


def _chattr_works(path: Path) -> bool:
    target = path / "probe"
    target.write_text("x")
    done = subprocess.run(["chattr", "+a", str(target)], capture_output=True, check=False)
    if done.returncode == 0:
        subprocess.run(["chattr", "-a", str(target)], capture_output=True, check=False)
    return done.returncode == 0


@pytest.mark.skipif(
    shutil.which("logrotate") is None or shutil.which("chattr") is None,
    reason="requires logrotate and chattr",
)
def test_forced_rotations_complete_and_every_file_ends_append_only(tmp_path: Path) -> None:
    if not _chattr_works(tmp_path):
        pytest.skip("this user or filesystem cannot set chattr +a")
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    conf = tmp_path / "conf"
    template = CONFIG.read_text(encoding="utf-8")
    conf.write_text(
        template.replace("/var/log/relay-shell", str(log_dir))
        .replace("create 0600 relay-shell relay-shell", "create 0600 root root")
        .replace("rotate 90", "rotate 3\n    dateformat -%s"),
        encoding="utf-8",
    )
    state = tmp_path / "state"
    active = log_dir / "audit.jsonl"
    try:
        for i in range(6):
            with active.open("a", encoding="utf-8") as handle:
                handle.write(f"record {i}\n")
            subprocess.run(["chattr", "+a", str(active)], check=True)
            # dateext with %s needs a distinct second per rotation
            subprocess.run(["sleep", "1"], check=True)
            done = subprocess.run(
                ["logrotate", "-f", "-s", str(state), str(conf)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert done.returncode == 0, done.stderr
            assert not done.stderr.strip(), done.stderr
        files = sorted(log_dir.iterdir())
        archives = [f for f in files if f.name.startswith("audit.jsonl-")]
        assert len(archives) == 3, [f.name for f in files]  # `rotate 3` pruned the rest
        listing = subprocess.run(
            ["lsattr", "-d", *map(str, files)], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        assert len(listing) == len(files)
        for line in listing:
            flags, _, name = line.partition(" ")
            assert "a" in flags, f"not append-only after rotation: {name}"
    finally:
        for f in log_dir.iterdir():
            subprocess.run(["chattr", "-a", str(f)], check=False, capture_output=True)
