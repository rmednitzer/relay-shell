"""Evaluate a paginated GitHub check snapshot; 0 passed, 2 pending, 1 refused."""

from __future__ import annotations

import json
import os
import sys
from typing import Any


def evaluate(
    pages: list[dict[str, Any]], sha: str, required: list[str], allowed_skipped: set[str]
) -> tuple[int, list[str]]:
    if not sha or not required or not all(name for name in required):
        raise ValueError("missing check policy")
    if not isinstance(pages, list) or not pages:
        raise ValueError("invalid paginated snapshot")
    latest: dict[str, dict[str, Any]] = {}
    for page in pages:
        for check in page["check_runs"]:
            # A same-name check from another app or revision is not evidence.
            if check["head_sha"] != sha or check["app"]["id"] != 15368:
                continue
            name = check["name"]
            if name not in latest or check["id"] > latest[name]["id"]:
                latest[name] = check
    pending, failed = [], []
    for name in required:
        check = latest.get(name)
        if check is None:
            pending.append(f"{name} (missing)")
        elif check["status"] != "completed":
            pending.append(f"{name} ({check['status']})")
        elif check["conclusion"] != "success" and not (
            check["conclusion"] == "skipped" and name in allowed_skipped
        ):
            failed.append(f"{name} ({check['conclusion']})")
    if failed:
        return 1, failed
    if pending:
        return 2, pending
    return 0, ["All protected dependencies passed."]


def main() -> int:
    try:
        code, messages = evaluate(
            json.load(sys.stdin),
            os.environ["TARGET_SHA"],
            os.environ["REQUIRED_CHECKS"].splitlines(),
            set(os.environ.get("ALLOWED_SKIPPED_CHECKS", "").splitlines()),
        )
    except (KeyError, TypeError, ValueError):
        print("Invalid or incomplete check snapshot/policy", file=sys.stderr)
        return 1
    print("; ".join(messages))
    return code


if __name__ == "__main__":
    sys.exit(main())
