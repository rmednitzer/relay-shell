---
name: Feature request
about: Propose a new tool, transport, auth provider, or capability.
title: "[feature] "
labels: ["enhancement"]
---

<!--
Before filing, check `docs/runbook.md` §7 to see if this is already in
the backlog. If it is, comment on this template with the backlog ID
(e.g. B-007) instead of opening a duplicate.

The runbook §6 has recipes for adding tools / transports / auth
providers / policy heuristics / redaction rules. If you plan to send
the PR yourself, skim the relevant recipe first.
-->

## Problem

<!-- The operational need this addresses. Not "add X" but "I cannot do
Y today because Z." -->

## Proposal

<!-- The change in one paragraph. Tool name (if applicable), default
tier, the parameters it takes, the shape of the response, the failure
modes. -->

## Capability impact

- [ ] Adds a new tool. Default tier: <!-- 0 / 1 / 2 / 3 -->
- [ ] Adds a new transport (`stdio` / `streamable-http` / other).
- [ ] Adds a new auth provider.
- [ ] Adds a new policy heuristic.
- [ ] Adds a new redaction rule.
- [ ] Adds a new env var (`RELAY_SHELL_*`).
- [ ] Adds a new runtime dependency.

## Alternatives considered

<!-- Existing tools that almost solve this; why they fall short. If the
operator can already accomplish this via composition (e.g. `shell_exec`
plus a script) and the only ask is ergonomics, say so explicitly. -->

## Documentation and tests this will need (best guess)

<!-- Reference the runbook §6 recipe. For a new tool that is:
- a row in `docs/tools.md`
- an entry in `tests/test_server.py::_EXPECTED` plus the `len()` assertion
- an entry in the README capability table
- a unit test of the underlying helper
- a wiring test that exercises the tool through FastMCP
- the `_INSTRUCTIONS` string in `server.py` -->

## Out of scope

<!-- Anything related you do *not* want addressed in the same PR. -->
