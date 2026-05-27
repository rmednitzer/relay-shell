"""Drift detection between shipped deploy templates and what's on disk.

The ``relay-shell verify-deploy`` CLI subcommand uses this module to compare
each template under ``deploy/`` against the file the installer is expected to
have laid down (e.g. ``/etc/systemd/system/relay-shell.service``). Operators
run this in production to confirm that no one has hand-edited the unit or
that the package upgrade actually replaced the file.

The comparison is byte-for-byte after stripping a single optional *leader
line* that the installer prepends (the Caddyfile marker
``# relay-shell:install-edge:managed``). Anything else is treated as drift.
"""

from __future__ import annotations

import importlib.resources as ir
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Status(StrEnum):
    OK = "OK"
    MISSING = "MISSING"
    DRIFT = "DRIFT"
    ABSENT_TEMPLATE = "ABSENT_TEMPLATE"


@dataclass(frozen=True)
class Finding:
    """One row in a verify-deploy report."""

    name: str
    template: str
    install_path: str
    status: Status
    detail: str = ""


@dataclass(frozen=True)
class Pair:
    name: str
    template_rel: str
    install_path: str
    leader: str | None = None


# The shipped templates this module knows about. The install paths match
# what ``deploy/install.sh`` / ``deploy/install-edge.sh`` lay down. Adding a
# new managed asset means appending a row here and adjusting the installer.
DEFAULT_PAIRS: tuple[Pair, ...] = (
    Pair(
        name="systemd-unit",
        template_rel="systemd/relay-shell.service",
        install_path="/etc/systemd/system/relay-shell.service",
    ),
    Pair(
        name="systemd-hardening",
        template_rel="systemd/relay-shell.service.d/hardening.conf",
        install_path="/etc/systemd/system/relay-shell.service.d/hardening.conf",
    ),
    Pair(
        name="logrotate",
        template_rel="logrotate/relay-shell",
        install_path="/etc/logrotate.d/relay-shell",
    ),
    Pair(
        name="caddyfile",
        template_rel="Caddyfile",
        install_path="/etc/caddy/Caddyfile",
        # install-edge.sh writes this marker as the first line so a future
        # run recognises its own file; strip it before comparing.
        leader="# relay-shell:install-edge:managed",
    ),
)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(f.status is Status.OK for f in self.findings)

    def by_status(self, status: Status) -> list[Finding]:
        return [f for f in self.findings if f.status is status]


def resolve_templates_dir(override: Path | None = None) -> Path:
    """Locate the deploy/ template directory.

    Search order:

    1. ``override`` if given (explicit ``--templates-dir`` flag).
    2. Packaged location: ``importlib.resources.files("relay_shell") /
       _deploy`` - present when the wheel was built with the
       ``force-include`` mapping in ``pyproject.toml``.
    3. Source-tree location: walk up from this file looking for a sibling
       ``deploy/`` directory that contains the expected templates. This
       covers the editable install (``pip install -e .``) case used in
       development and CI.

    Raises ``FileNotFoundError`` if none of these resolve.
    """
    if override is not None:
        return override
    try:
        resource = ir.files("relay_shell").joinpath("_deploy")
        pkg_path = Path(str(resource))
        if pkg_path.is_dir() and (pkg_path / "Caddyfile").is_file():
            return pkg_path
    except (ModuleNotFoundError, AttributeError):
        pass
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "deploy"
        if candidate.is_dir() and (candidate / "Caddyfile").is_file():
            return candidate
    raise FileNotFoundError(
        "deploy templates not found - pass --templates-dir or install the wheel"
    )


def _resolve_install_path(install_path: str, install_prefix: Path | None) -> Path:
    if install_prefix is None:
        return Path(install_path)
    # Treat install_prefix as a chroot-style root for tests: it mirrors the
    # absolute install_path under itself, preserving the full directory shape.
    return install_prefix / install_path.lstrip("/")


def verify_pair(pair: Pair, templates_dir: Path, install_prefix: Path | None) -> Finding:
    tpl_path = templates_dir / pair.template_rel
    install_path = _resolve_install_path(pair.install_path, install_prefix)
    if not tpl_path.is_file():
        return Finding(
            name=pair.name,
            template=str(tpl_path),
            install_path=str(install_path),
            status=Status.ABSENT_TEMPLATE,
            detail=f"template file {tpl_path} not found",
        )
    if not install_path.is_file():
        return Finding(
            name=pair.name,
            template=str(tpl_path),
            install_path=str(install_path),
            status=Status.MISSING,
            detail=f"{install_path} does not exist",
        )
    try:
        # Pin UTF-8: drift detection is byte-exact and the default
        # locale encoding varies across hosts. Wrap the reads so a
        # TOCTOU between ``is_file()`` above and these reads (or a
        # permission-denied after the check) becomes a structured
        # Finding rather than a raise - ``verify_deploy``'s contract
        # is "never raises into the caller".
        template = tpl_path.read_text(encoding="utf-8")
        installed = install_path.read_text(encoding="utf-8")
    except OSError as exc:
        return Finding(
            name=pair.name,
            template=str(tpl_path),
            install_path=str(install_path),
            status=Status.MISSING,
            detail=f"could not read: {exc}",
        )
    if pair.leader and installed.startswith(pair.leader):
        installed = installed[len(pair.leader) :].lstrip("\n")
    if installed == template:
        return Finding(
            name=pair.name,
            template=str(tpl_path),
            install_path=str(install_path),
            status=Status.OK,
        )
    return Finding(
        name=pair.name,
        template=str(tpl_path),
        install_path=str(install_path),
        status=Status.DRIFT,
        detail="deployed content does not match template",
    )


def verify_deploy(
    templates_dir: Path | None = None,
    install_prefix: Path | None = None,
    pairs: tuple[Pair, ...] = DEFAULT_PAIRS,
) -> Report:
    """Run drift detection across every shipped template.

    Always returns a ``Report``; it never raises into the caller. Resolution
    failures for the templates directory become ``ABSENT_TEMPLATE`` findings
    for every pair so the CLI exit code still flags the operator.
    """
    try:
        base = resolve_templates_dir(templates_dir)
    except FileNotFoundError as exc:
        return Report(
            findings=[
                Finding(
                    name=p.name,
                    template=p.template_rel,
                    install_path=p.install_path,
                    status=Status.ABSENT_TEMPLATE,
                    detail=str(exc),
                )
                for p in pairs
            ]
        )
    return Report(findings=[verify_pair(p, base, install_prefix) for p in pairs])
