"""Entrypoint: ``relay_shell`` / ``python -m relay_shell``.

Transport and all behaviour come from ``RELAY_SHELL_*`` environment variables (see
``.env.example``). Logging goes to **stderr** only: the stdio transport owns
stdout/stdin for JSON-RPC, so a stray stdout write would corrupt the stream.
"""

from __future__ import annotations

import argparse
import logging
import sys

from .config import get_settings
from .server import Relay, build_server


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
        # the OAuth provider. Both validate the side-effecting parts of the
        # config (audit path open, ssh_config parse, OAuth state dir).
        build_server(settings)
        # build_server holds the Relay internally; instantiate one alongside
        # so we can inspect the audit sink's degraded flag. The instantiation
        # is cheap and benign (audit file is opened append-only).
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


def main(argv: list[str] | None = None) -> int:
    """Build and run the server. Returns a process exit code."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    _configure_logging()

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
    try:
        if settings.transport == "http":
            server.run(transport="streamable-http")
        else:
            server.run(transport="stdio")
    except KeyboardInterrupt:
        log.info("relay_shell stopped (interrupt)")
        return 0
    except Exception as exc:  # noqa: BLE001
        log.error("relay_shell exited with error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
