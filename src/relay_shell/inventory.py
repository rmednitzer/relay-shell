"""Host inventory: ``~/.ssh/config`` plus an optional JSON inventory file.

asyncssh parses ``ssh_config`` natively at connect time (including
``ProxyJump``), so for *connecting* we hand the config path straight to it and
only overlay explicit overrides. This module additionally provides a flat,
listable view (the ``ssh_hosts`` tool) and a resolver that lets a JSON
inventory file augment or override config-defined aliases.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["HostSpec", "Inventory"]


@dataclass(frozen=True)
class HostSpec:
    name: str
    hostname: str
    user: str | None = None
    port: int | None = None
    identity_file: str | None = None
    jump: str | None = None
    known_hosts: str | None = None
    source: str = "explicit"

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "hostname": self.hostname,
            "user": self.user,
            "port": self.port,
            "identity_file": self.identity_file,
            "jump": self.jump,
            "source": self.source,
        }


def _expand(path: str) -> Path:
    return Path(path).expanduser()


def _parse_ssh_config(path: Path) -> dict[str, HostSpec]:
    """A deliberately small ssh_config reader for *listing/resolving*.

    It understands ``Host``, ``HostName``, ``User``, ``Port``,
    ``IdentityFile`` and ``ProxyJump``. Wildcard ``Host`` patterns are skipped
    for the flat listing (asyncssh still honours them when connecting).
    """
    if not path.is_file():
        return {}
    hosts: dict[str, HostSpec] = {}
    aliases: list[str] = []
    cur: dict[str, str] = {}

    def _flush() -> None:
        for alias in aliases:
            if any(c in alias for c in "*?!"):
                continue
            hosts[alias] = HostSpec(
                name=alias,
                hostname=cur.get("hostname", alias),
                user=cur.get("user"),
                port=int(cur["port"]) if cur.get("port", "").isdigit() else None,
                identity_file=cur.get("identityfile"),
                jump=cur.get("proxyjump"),
                source="ssh_config",
            )

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and " " not in line.split("=", 1)[0].strip():
            key, _, val = line.partition("=")
        else:
            key, _, val = line.partition(" ")
        key = key.strip().lower()
        val = val.strip()
        if not key:
            continue
        if key == "host":
            _flush()
            aliases = val.split()
            cur = {}
        elif key in {"hostname", "user", "port", "identityfile", "proxyjump"}:
            cur.setdefault(key, val)
    _flush()
    return hosts


def _load_inventory_file(path: Path) -> dict[str, HostSpec]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, HostSpec] = {}
    for name, spec in data.items():
        if not isinstance(spec, dict):
            continue
        port_val = spec.get("port")
        out[name] = HostSpec(
            name=name,
            hostname=str(spec.get("hostname", spec.get("host", name))),
            user=spec.get("user"),
            port=int(port_val)
            if isinstance(port_val, (int, str)) and str(port_val).isdigit()
            else None,
            identity_file=spec.get("identity_file") or spec.get("identityfile"),
            jump=spec.get("jump") or spec.get("proxyjump"),
            known_hosts=spec.get("known_hosts"),
            source="inventory",
        )
    return out


@dataclass
class Inventory:
    ssh_config_path: str
    inventory_path: str
    _hosts: dict[str, HostSpec] = field(default_factory=dict)

    def load(self) -> Inventory:
        merged = _parse_ssh_config(_expand(self.ssh_config_path))
        if self.inventory_path:
            merged.update(_load_inventory_file(_expand(self.inventory_path)))
        self._hosts = merged
        return self

    @property
    def ssh_config_file(self) -> str | None:
        p = _expand(self.ssh_config_path)
        return str(p) if p.is_file() else None

    def resolve(self, alias: str) -> HostSpec:
        """Return a known spec or a passthrough spec (asyncssh resolves it)."""
        if alias in self._hosts:
            return self._hosts[alias]
        if "@" in alias:
            user, _, host = alias.partition("@")
            return HostSpec(name=alias, hostname=host, user=user or None)
        return HostSpec(name=alias, hostname=alias)

    def hosts(self) -> list[HostSpec]:
        return sorted(self._hosts.values(), key=lambda h: h.name)
