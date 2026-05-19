"""Entrypoint: ``relay_shell`` / ``python -m relay_shell``.

Transport and all behaviour come from ``RELAY_SHELL_*`` environment variables (see
``.env.example``). Logging goes to **stderr** only: the stdio transport owns
stdout/stdin for JSON-RPC, so a stray stdout write would corrupt the stream.
"""

from __future__ import annotations

import logging
import sys

from .config import get_settings
from .server import build_server


def _configure_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    stderr = logging.StreamHandler(sys.stderr)
    stderr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(stderr)


def main() -> int:
    """Build and run the server. Returns a process exit code."""
    _configure_logging()
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
