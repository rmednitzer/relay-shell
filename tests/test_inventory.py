from __future__ import annotations

import json
from pathlib import Path

from relay_shell.inventory import Inventory


def test_parse_ssh_config(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text(
        "Host web1\n"
        "    HostName 10.0.0.1\n"
        "    User deploy\n"
        "    Port 2222\n"
        "    IdentityFile ~/.ssh/id_web\n"
        "Host bastion\n"
        "    HostName bastion.example.com\n"
        "Host db1\n"
        "    HostName 10.0.0.2\n"
        "    ProxyJump bastion\n"
        "Host *\n"
        "    ServerAliveInterval 30\n",
        encoding="utf-8",
    )
    inv = Inventory(str(cfg), "").load()
    hosts = {h.name: h for h in inv.hosts()}
    assert set(hosts) == {"web1", "bastion", "db1"}  # wildcard skipped
    assert hosts["web1"].hostname == "10.0.0.1"
    assert hosts["web1"].user == "deploy"
    assert hosts["web1"].port == 2222
    assert hosts["db1"].jump == "bastion"
    assert inv.ssh_config_file == str(cfg)


def test_inventory_file_overrides(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text("Host web1\n  HostName 10.0.0.1\n", encoding="utf-8")
    invf = tmp_path / "inv.json"
    invf.write_text(
        json.dumps(
            {
                "web1": {"hostname": "192.168.1.1", "user": "root"},
                "edge": {"host": "edge.local", "port": 22, "jump": "bastion"},
            }
        ),
        encoding="utf-8",
    )
    inv = Inventory(str(cfg), str(invf)).load()
    by = {h.name: h for h in inv.hosts()}
    assert by["web1"].hostname == "192.168.1.1"  # overridden
    assert by["web1"].source == "inventory"
    assert by["edge"].jump == "bastion"


def test_resolve_passthrough_and_userhost(tmp_path: Path) -> None:
    inv = Inventory(str(tmp_path / "none"), "").load()
    assert inv.resolve("h1.example.com").hostname == "h1.example.com"
    spec = inv.resolve("alice@h2")
    assert spec.user == "alice" and spec.hostname == "h2"
    assert inv.ssh_config_file is None
