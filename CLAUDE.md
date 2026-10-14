# Claude Code guidance: relay-shell

@AGENTS.md

## Use of this file

The imported AGENTS.md is the canonical repository workflow and secure development
contract. Read SECURITY.md before security-sensitive changes and applicable
source, tests and ADRs before implementation. Read nested CLAUDE.md/AGENTS.md files
for touched subtrees; do not infer that an import or prompt enforces a runtime
security control. Keep durable rules in AGENTS.md rather than duplicating them here.

Preserve task scope, existing work and required checks. Use deterministic local
tests by default; verify operation identity and postconditions before retrying a
timed-out mutation. Report skipped checks and uncertainty explicitly.
