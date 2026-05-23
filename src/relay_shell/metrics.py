"""In-memory Prometheus counter + gauge registry for the HTTP transport.

The audit log is the source of truth for what happened (one JSONL record per
tool call, output-hashed). Metrics are *only* for dashboards: low-cardinality
counters for tool-call volume by tool / tier / mode / outcome, plus three
liveness gauges (active sessions, active forwards, audit-degraded). They live
in process memory, reset on restart, and are exposed at ``GET /metrics`` on
the HTTP transport only.

Exposition is hand-rolled (no `prometheus_client` dep). The Prometheus text
exposition format is simple enough that taking on a runtime dependency for
five metric names is poor cost-vs-value; the escape rules used here match
the spec (`\\`, `\"`, `\n` only inside label values; metric values are
floats or integers serialised with `repr`).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from threading import Lock

# Public metric names. Kept here as constants so docs/tests can reference
# them without hard-coding the strings in three places.
TOOL_CALLS_TOTAL = "relay_shell_tool_calls_total"
ACTIVE_SESSIONS = "relay_shell_active_sessions"
ACTIVE_FORWARDS = "relay_shell_active_forwards"
AUDIT_DEGRADED = "relay_shell_audit_degraded"

_HELP: dict[str, str] = {
    TOOL_CALLS_TOTAL: "Total tool invocations, labelled by tool/tier/mode/outcome.",
    ACTIVE_SESSIONS: "Current count of live local/SSH PTY sessions.",
    ACTIVE_FORWARDS: "Current count of live SSH port forwards.",
    AUDIT_DEGRADED: "1 if the audit sink is degraded; 0 otherwise.",
}

_TYPES: dict[str, str] = {
    TOOL_CALLS_TOTAL: "counter",
    ACTIVE_SESSIONS: "gauge",
    ACTIVE_FORWARDS: "gauge",
    AUDIT_DEGRADED: "gauge",
}

# Order matters: HELP+TYPE+samples block per metric, then the next metric.
_GAUGE_ORDER: tuple[str, ...] = (ACTIVE_SESSIONS, ACTIVE_FORWARDS, AUDIT_DEGRADED)

_LabelKey = tuple[tuple[str, str], ...]


def _escape_label_value(value: str) -> str:
    # Per the Prometheus text format spec only these three characters need
    # escaping inside a label value (everything else, including spaces and
    # `{}`, is allowed verbatim).
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    parts = [f'{k}="{_escape_label_value(v)}"' for k, v in sorted(labels.items())]
    return "{" + ",".join(parts) + "}"


class Metrics:
    """Thread-safe in-memory counter + gauge-provider registry.

    Counters are stored as ``{metric_name: {label_tuple: count}}``. Gauges are
    callables: the renderer pulls the live value at scrape time so the metric
    cannot drift from the underlying source of truth.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[str, dict[_LabelKey, int]] = defaultdict(lambda: defaultdict(int))
        self._gauge_providers: dict[str, Callable[[], float]] = {}

    # --- writers -----------------------------------------------------------

    def inc_tool_call(self, *, tool: str, tier: int, mode: str, outcome: str) -> None:
        """Bump the per-tool counter. ``outcome`` is ``ok|denied|error``."""
        labels: _LabelKey = (
            ("mode", mode),
            ("outcome", outcome),
            ("tier", str(int(tier))),
            ("tool", tool),
        )
        with self._lock:
            self._counters[TOOL_CALLS_TOTAL][labels] += 1

    def register_gauge(self, name: str, provider: Callable[[], float]) -> None:
        if name not in _TYPES or _TYPES[name] != "gauge":
            raise ValueError(f"unknown or non-gauge metric: {name!r}")
        with self._lock:
            self._gauge_providers[name] = provider

    # --- readers -----------------------------------------------------------

    def snapshot_counters(self) -> dict[str, dict[_LabelKey, int]]:
        with self._lock:
            return {name: dict(values) for name, values in self._counters.items()}

    def render(self) -> str:
        """Return the Prometheus text exposition (UTF-8, trailing newline)."""
        lines: list[str] = []

        # Counter block(s).
        counters = self.snapshot_counters()
        for name in (TOOL_CALLS_TOTAL,):
            lines.append(f"# HELP {name} {_HELP[name]}")
            lines.append(f"# TYPE {name} {_TYPES[name]}")
            for label_tuple, value in sorted(counters.get(name, {}).items()):
                labels = dict(label_tuple)
                lines.append(f"{name}{_format_labels(labels)} {value}")

        # Gauge block(s). Each metric appears even if no provider is
        # registered so dashboards see the metric exists (samples omitted).
        with self._lock:
            providers = dict(self._gauge_providers)
        for name in _GAUGE_ORDER:
            lines.append(f"# HELP {name} {_HELP[name]}")
            lines.append(f"# TYPE {name} {_TYPES[name]}")
            provider = providers.get(name)
            if provider is None:
                continue
            try:
                gauge_value = float(provider())
            except Exception:  # noqa: BLE001
                # A gauge source that misbehaves must not break the scrape:
                # emit nothing for this metric this scrape and continue.
                continue
            lines.append(f"{name} {gauge_value}")

        lines.append("")  # trailing newline required by the exposition format
        return "\n".join(lines)
