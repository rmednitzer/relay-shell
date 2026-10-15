# Release signing trust and historical verification

The production release verifier loads authorized SSH signing keys from the
protected main branch rather than the tagged checkout. Release commits must
be ancestors of protected main. Tag creation is owner-restricted, updates
and deletion are denied, and immutable GitHub releases are enabled.

## Signing evidence

Recorded 2026-10-12 for v0.1.0 to v0.3.0 and 2026-10-15 for v0.4.0.

| Tag | Current signer allowlist | Signing key |
| --- | --- | --- |
| v0.1.0 | Rejected | Previous GitHub-registered SSH key |
| v0.2.0 | Rejected | Previous GitHub-registered SSH key |
| v0.3.0 | Accepted | Current authorized SSH key |
| v0.4.0 | Accepted | Current authorized SSH key |

All four tag targets are ancestors of main. The v0.4.0 tag object
`5b7c9480185c7b2f19a340052c25966090e3e334` targets commit
`83a08789035713ab77876a3a5fb080ebc0d64b06`; `git tag -v` against
`deploy/release-signing.pub` on main reports a good signature from the current
key. The previous signer fingerprint
is SHA256:l987e6ZYlQyiCwlIdHEsYT9RCnuAAGC3lqqVsZvyt3c. The current
fingerprint is SHA256:toiPb4c4HuVxGNLbPkfHOnRDO5k7ZvzownZfvmVQ7Lk.
GitHub currently registers both keys; registration does not prove either
key was authorized when a specific historical artifact was published.

## Policy

- Do not add historical signing keys to the production release allowlist.
- Preserve and verify historical signatures only against an independently
  retained, dated forensic allowlist, never a key from a tag's checkout.
- Record tag-object ID, target commit, signer fingerprint and provenance.
- Verify published package digests and release attestations independently.
  A valid Git tag signature is not proof of binary artifact integrity.
- Do not replay historical tags through PyPI or the release publisher.
  Rebuilds for comparison must be offline or isolated without publication
  and deployment permissions.
- Rotate the production key by reviewed changes on protected main, test a
  new signed tag, and preserve the superseded key only as historical evidence.
- If original artifacts or identities are unavailable, mark that aspect
  unverified rather than granting retrospective trust.

This policy is scoped to release provenance, not a claim that existing
PyPI/GitHub artifacts have been reproduced.
