# ADR 0008: Operating-guidance MCP prompt, audited like a resource read

- Status: Accepted
- Date: 2026-06-08

## Context

The server tells a client *what* tools exist (the FastMCP `instructions`
string, surfaced at initialize) and *what each one does* (the per-tool
`description`, taken from the docstring). It gave no *detailed* guidance on
**when to use which tool**, above all the selection cliff between a one-shot
command (`shell_exec` / `ssh_exec`) and a persistent PTY session
(`shell_spawn` / `ssh_spawn` driven by the `session_*` tools), and that the
spawn and session tools are one workflow rather than alternatives.

Validated against the pinned SDK (`mcp==1.27.1`): server `instructions` is for
concise guidance conveyed once at initialize; per-tool `description` is "what
this tool does"; and **MCP prompts are the canonical mechanism for detailed,
reusable, client-pullable usage guidance**. relay-shell registered no prompts.

A prompt fetch is a *model-context pull*, the same class of action as a
resource read. Under ADR 0002 (no sandbox, safety via compensating controls)
auditability is the load-bearing control, and resource reads are already
audited (tier 0, `tool="resource:<name>"`) so an operator can see what context
the model pulls in. A new context-pull surface must honour that invariant, not
open a side channel around it.

## Decision

Register one no-argument MCP prompt, **`operating_guide`**, that returns a
detailed operating guide: tool selection (one-shot vs PTY session, `exec` vs
`script`, local vs remote), the spawn-plus-`session_*` workflow with a worked
loop, the fleet and file-transfer entry points, and the bounded, audited
execution model with its error grammar.

Audit every fetch:

- Each `prompts/get` is recorded as a tier-0 audit line with a **stable**
  `tool="prompt:operating_guide"` label, bypassing `Relay.run` exactly as a
  resource read does: there is no command text to classify, no timeout, and no
  exit code, so admission control does not apply. The same `/metrics`
  tool-call counter is ticked.
- The body is bounded by the same `max_output` cap resources observe.
- `prompts/list` returns metadata only and **does not** call the function, so
  the audit fires on a real fetch, never on discovery.

The audit-record **shape is unchanged**: a prompt read reuses the existing
tier-0 record (`ts`, `tool`, `tier`, `denied`, `args`, `output_sha256`,
`output_len`, `exit_code`). Only the `tool` namespace gains a `prompt:` prefix,
alongside the existing `resource:` and `syscall_notify` labels. The output body
is hashed, never written, as everywhere else.

## Consequences

- FastMCP now advertises the `prompts/list` / `prompts/get` surface. Clients
  that ignore prompts are unaffected; the tool and resource surfaces are
  untouched.
- The "every context the model pulls in is audited" invariant now spans tools,
  resources, **and** prompts: one more bounded `tool:` namespace, no new record
  fields.
- Further prompts are a routine addition (one more `prompt:<name>` label
  through the same helper), not a posture change.
- `/metrics` tool-call cardinality grows by one bounded label per prompt; the
  label is a server-authored constant, never a user-controlled string.

## Rejected alternatives

- **A client-specific `skills/` file read off the filesystem.** Couples the
  guidance to one client and, the deciding factor, makes it a model-context
  pull *outside* the audit boundary, contrary to ADR 0002.
- **Putting the full guide in the `instructions` string.** A long guide bloats
  every session's handshake and cannot be pulled on demand. The concise
  selection heuristic stays in `instructions`; the detailed form is the prompt.
- **Routing prompt fetches through `Relay.run`.** There is no command to
  classify, no timeout, and no exit code. The resource precedent — audited but
  not admitted — is the correct shape.
