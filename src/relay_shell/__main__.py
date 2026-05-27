"""Entrypoint: ``relay_shell`` / ``python -m relay_shell``.

Transport and all behaviour come from ``RELAY_SHELL_*`` environment variables (see
``.env.example``). Logging goes to **stderr** only: the stdio transport owns
stdout/stdin for JSON-RPC, so a stray stdout write would corrupt the stream.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import signal
import sys
from pathlib import Path

from .config import get_settings
from .server import Relay, build_server
from .verifier import Status, verify_deploy


def _configure_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    stderr = logging.StreamHandler(sys.stderr)
    stderr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(stderr)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relay-shell",
        description=(
            "MCP server for governed shell and SSH operations. Behaviour is "
            "configured via RELAY_SHELL_* environment variables; see "
            ".env.example for the full surface."
        ),
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help=(
            "Load settings, construct the server (audit sink, policy, "
            "inventory, OAuth if enabled) WITHOUT starting a transport, "
            "and exit 0 if everything initialized cleanly. Exits 2 on "
            "invalid configuration or a degraded audit sink. Intended "
            "for CI pipelines that bake an image."
        ),
    )
    parser.add_argument(
        "--verify-deploy",
        action="store_true",
        help=(
            "Compare each shipped deploy template (systemd unit + "
            "drop-in, logrotate, Caddyfile) against the file the "
            "installer is expected to have laid down on this host. "
            "Exits 0 if every entry matches, 2 if any DRIFT / MISSING / "
            "ABSENT_TEMPLATE is found. Intended for production drift "
            "detection and image-bake validation."
        ),
    )
    parser.add_argument(
        "--templates-dir",
        type=Path,
        default=None,
        help=(
            "Override the shipped-templates lookup. Default: the wheel's "
            "packaged copy, falling back to deploy/ next to this file."
        ),
    )
    parser.add_argument(
        "--install-prefix",
        type=Path,
        default=None,
        help=(
            "Treat this directory as a chroot-style root: each absolute "
            "install path is rebased under it. Used by tests and "
            "image-bake validation."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_out",
        help=("Emit machine-readable output for --verify-deploy (ignored for other subcommands)."),
    )
    return parser


def _check_config() -> int:
    """Validate config + build the server without starting a transport.

    Returns 0 on success, 2 on any initialization failure or a degraded
    audit sink. All output goes to stderr so the stdio transport's
    contract is preserved even when this is called from a parent process
    that pipes our streams.
    """
    try:
        settings = get_settings()
    except Exception as exc:  # noqa: BLE001
        print(f"relay_shell: invalid configuration: {exc}", file=sys.stderr)
        return 2
    try:
        # build_server registers every tool and (for http+auth) constructs
        # the OAuth provider, validating audit path, ssh_config parse, and
        # the OAuth state dir as side effects of construction. The Relay
        # built inside is exposed as `mcp.relay` so we can read the audit
        # degraded flag here without opening the audit file a second time.
        server = build_server(settings)
        relay: Relay | None = getattr(server, "relay", None)
        if relay is None:  # defensive — build_server is expected to set it
            relay = Relay(settings)
    except Exception as exc:  # noqa: BLE001
        print(f"relay_shell: build_server failed: {exc}", file=sys.stderr)
        return 2

    if relay.audit.degraded:
        print(
            f"relay_shell: audit sink degraded ({relay.audit.degraded_reason}); "
            f"refuse this configuration for production deployment.",
            file=sys.stderr,
        )
        return 2

    print(
        f"relay_shell: config OK "
        f"(transport={settings.transport}, "
        f"policy={settings.policy_mode}, "
        f"audit={settings.audit_path})",
        file=sys.stderr,
    )
    return 0


def _verify_deploy(
    templates_dir: Path | None,
    install_prefix: Path | None,
    json_out: bool,
) -> int:
    """Run drift detection and print a report.

    Returns 0 if every finding is OK, 2 otherwise. Errors never escape as
    tracebacks: ``verify_deploy()`` itself folds template-resolution failures
    into structured ``ABSENT_TEMPLATE`` findings.
    """
    report = verify_deploy(templates_dir=templates_dir, install_prefix=install_prefix)

    if json_out:
        payload = {
            "ok": report.ok,
            "findings": [
                {
                    "name": f.name,
                    "template": f.template,
                    "install_path": f.install_path,
                    "status": f.status.value,
                    "detail": f.detail,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        # Column widths chosen so the longest name + status + path stays
        # under 100 cols for typical install paths.
        name_w = max((len(f.name) for f in report.findings), default=0)
        status_w = max((len(f.status.value) for f in report.findings), default=0)
        for f in report.findings:
            line = f"{f.name:<{name_w}}  {f.status.value:<{status_w}}  {f.install_path}"
            if f.detail and f.status is not Status.OK:
                line += f"  ({f.detail})"
            print(line)
        if report.ok:
            print("relay-shell: verify-deploy OK", file=sys.stderr)
        else:
            drift = len(report.by_status(Status.DRIFT))
            missing = len(report.by_status(Status.MISSING))
            absent = len(report.by_status(Status.ABSENT_TEMPLATE))
            print(
                f"relay-shell: verify-deploy FAILED "
                f"(drift={drift}, missing={missing}, absent_template={absent})",
                file=sys.stderr,
            )

    return 0 if report.ok else 2


def _install_sigterm_handler() -> None:
    """Convert SIGTERM into a KeyboardInterrupt so the shutdown finally
    block in ``main`` runs.

    systemd's ``systemctl stop`` and container orchestrators deliver
    SIGTERM by default. Python's default SIGTERM handler terminates the
    process without raising, which would skip ``relay.sessions.shutdown()``
    and ``relay.ssh.close_all()`` and leave long-running PTY children and
    SSH forwards behind. Re-raising as KeyboardInterrupt threads through
    the same path Ctrl-C uses.
    """

    def _on_sigterm(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    with contextlib.suppress(ValueError):  # main thread only
        signal.signal(signal.SIGTERM, _on_sigterm)


def main(argv: list[str] | None = None) -> int:
    """Build and run the server. Returns a process exit code."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    _configure_logging()
    _install_sigterm_handler()

    if args.verify_deploy:
        return _verify_deploy(args.templates_dir, args.install_prefix, args.json_out)

    if args.check_config:
        return _check_config()

    log = logging.getLogger("relay_shell")
    try:
        settings = get_settings()
    except Exception as exc:  # noqa: BLE001
        print(f"relay_shell: invalid configuration: {exc}", file=sys.stderr)
        return 2

    server = build_server(settings)
    log.info(
        "relay_shell starting (transport=%s, policy=%s, audit=%s)",
        settings.transport,
        settings.policy_mode,
        settings.audit_path,
    )
    exit_code = 0
    try:
        if settings.transport == "http":
            server.run(transport="streamable-http")
        else:
            server.run(transport="stdio")
    except KeyboardInterrupt:
        log.info("relay_shell stopped (interrupt)")
    except Exception as exc:  # noqa: BLE001
        log.error("relay_shell exited with error: %s", exc)
        exit_code = 1
    finally:
        # Graceful shutdown: tear down live PTY sessions and the SSH
        # connection cache + forwards so long-running children are reaped
        # instead of waiting on GC / process exit.
        relay: Relay | None = getattr(server, "relay", None)
        if relay is not None:
            with contextlib.suppress(Exception):
                asyncio.run(_shutdown(relay))
    return exit_code


async def _shutdown(relay: Relay) -> None:
    with contextlib.suppress(Exception):
        await relay.sessions.shutdown()
    with contextlib.suppress(Exception):
        await relay.ssh.close_all()


if __name__ == "__main__":
    raise SystemExit(main())
