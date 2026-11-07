# Release signing trust and historical verification

The production release verifier loads authorized SSH signing keys from the
protected main branch rather than the tagged checkout. Release commits must
be ancestors of protected main. Tag creation is owner-restricted, updates
and deletion are denied, and immutable GitHub releases are enabled. These
repository settings were rechecked on 2026-11-07; they are external controls,
not properties established by checking out the source.

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
The earlier record notes GitHub registration of both keys; registration does
not prove either key was authorized when a specific historical artifact was published.

## Verification update: 2026-11-07

Rechecked against main commit
`e7f4256b63477fd2da6bcad8d2437d07cc2c17f5`, using its
`deploy/release-signing.pub` rather than a trust file from a tag. All seven
tag targets, v0.1.0 through v0.5.2, are ancestors of that main revision.
The v0.1.0/v0.2.0 signatures remain cryptographically recognizable but rejected
by the current allowlist (`No principal matched`); v0.3.0 through v0.5.2
are accepted with the current fingerprint recorded above.

| Tag | Annotated tag object | Target commit | Current allowlist |
| --- | --- | --- | --- |
| v0.5.0 | `d5580d2a9a031d4caf502a4aec5a8104c3ba16d6` | `7e790ca633dad0b8c1632796104fe40d55866277` | Accepted |
| v0.5.1 | `f20dc3ba95c4d8819aa692649f6f1619dbcc8e34` | `efe9243b2c2e33718eed9edab72fad0449e9ffb0` | Accepted |
| v0.5.2 | `4a6bb6f645549a66c22dd9e80343beecfdcba51f` | `5da388ee71ba779e1cb939e69280c9966cf03533` | Accepted |

To repeat for each tag from an independently trusted main checkout:

```bash
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=deploy/release-signing.pub tag -v v0.5.2
git rev-parse v0.5.2
git rev-parse 'v0.5.2^{}'
git merge-base --is-ancestor 'v0.5.2^{}' origin/main
```

The API checks on the same date observed active `main-protection` with no
bypass actors; owner-only creation of `refs/tags/v*` through
`release-tag-creators`; update/deletion refusal with no bypass actors through
`release-tag-integrity`; and `immutable-releases.enabled=true`.
These settings do not themselves verify a tag signature or main ancestry.
No tag was created, replaced or replayed. This verification covers Git source
identity and repository settings; it does not reproduce packages or verify
published SBOM/package bytes or attestations.

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
