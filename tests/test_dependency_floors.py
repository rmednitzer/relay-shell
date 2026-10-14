"""A14-D14: declared dependency floors must not be lower than what `mcp` itself requires."""

from __future__ import annotations

import tomllib
from importlib.metadata import requires, version
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent


def _floor(req: Requirement) -> Version | None:
    floors = [Version(s.version) for s in req.specifier if s.operator in (">=", "==", "~=", ">")]
    return max(floors) if floors else None


def _declared() -> dict[str, Requirement]:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    out: dict[str, Requirement] = {}
    for dep in cfg["project"]["dependencies"]:
        req = Requirement(dep)
        out[req.name.lower()] = req
    return out


def _required_by(package: str) -> dict[str, Requirement]:
    out: dict[str, Requirement] = {}
    for dep in requires(package) or []:
        req = Requirement(dep)
        if req.marker is not None and not req.marker.evaluate({"extra": ""}):
            continue
        out.setdefault(req.name.lower(), req)
    return out


@pytest.mark.parametrize("package", ["mcp", "pydantic-settings", "asyncssh"])
def test_declared_floors_cover_what_dependencies_require(package: str) -> None:
    declared = _declared()
    for name, upstream in _required_by(package).items():
        mine = declared.get(name)
        up_floor = _floor(upstream)
        if mine is None or up_floor is None:
            continue
        my_floor = _floor(mine)
        assert my_floor is not None, f"{name} has no lower bound but {package} needs {up_floor}"
        assert my_floor >= up_floor, (
            f"pyproject allows {name}>={my_floor} but {package} {version(package)} "
            f"requires {name}>={up_floor}"
        )


def test_http_extra_is_an_empty_alias() -> None:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert cfg["project"]["optional-dependencies"]["http"] == []
