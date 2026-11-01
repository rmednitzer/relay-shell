# Frozen historical upgrade fixture

This fixture identifies the annotated, SSH-signed `v0.3.0` source and a complete
Python 3.12 HTTP dependency profile. It is a newly qualified test environment,
not a reconstruction of a historical host. It is never installed by the current
production installer or included as current runtime requirements.

`baseline.json` binds the tag object, source commit, package/SDK versions and both
input/output dependency hashes. The CI driver verifies the tag against signer
material from protected main and checks main ancestry before executing baseline
code. Checkouts, state and generated credentials exist only on an empty disposable
hosted VM. Only source/artifact identities and verification outcomes are retained.

The closure was generated with uv 0.12.23 using the command in `runtime.lock`.
Changes require reviewed manifest hashes and a new successful qualification;
updating a version string alone is insufficient. New dependency findings fail
qualification unless their applicability receives a separate reviewed disposition.
Changing signer policy, source/lock bytes, transport mode or upstream advisory
conditions invalidates the existing admission/disposition evidence.

## CVE-2026-59951 / GHSA-84m7-p3x7-pcfv

The audit reports this finding for mcp 1.28.1. It is retained in the qualification
receipt, rather than silently counted as a clean baseline. The upstream advisory
excludes servers explicitly using `stateless_http=True` on SDK 1.12.0 or later:
https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-84m7-p3x7-pcfv

The admitted v0.3.0 source sets that literal in its server constructor. The driver
checks it before baseline execution and performs two authenticated initializations
without receiving a session ID, both before upgrade and after restored rollback.
The audit validator accepts only this exact package/version/advisory combination,
requires complete matching dependency coverage, refuses skipped packages, and
fails on unknown findings or changed upstream exclusion text. This is a bounded
not-affected disposition for the fixture, not a patch, a global suppression or a
recommendation to deploy an old SDK. Current-runtime audits remain unchanged.

The newly published MCP advisories are also retained in the receipt, with their
complete pip-audit descriptions hash-bound in `advisory-description-hashes.json`.
The redirect and output-schema findings apply to MCP clients, while this signed
source only constructs an MCP server; the rehearsal checks that its source imports
none of the affected client APIs. The audience finding requires a shared issuer for
multiple resource servers. This isolated rehearsal uses one local issuer and one
resource server; a live proof confirms that a separately-instantiated local token
provider refuses the first provider's opaque token. These are fixture-specific
not-affected decisions, not a claim that the old package is safe in other
deployments. Renew review if an advisory description, fixture role, or token
provider behavior changes:

- https://github.com/advisories/GHSA-5h93-6whr-6q8j
- https://github.com/advisories/GHSA-rwrf-2pqf-9j8j
- https://github.com/advisories/GHSA-w4fh-qvv9-3v23

The baseline also stores raw OAuth credentials. Tests generate temporary fixture
grants, verify their migration to hashed storage and verify that current code
refuses legacy grants lacking resource binding. Reauthorization is required.
Rollback preserves the accepted audit tail and clears grants/codes before the old
service starts; snapshot tokens must not silently become usable again. This does
not preserve every newer security policy or make the old release suitable for an
operational downgrade. No operational hosts, clients, credentials or TLS are used.

The current SDK revocation request model requires a `client_secret` field even
for this public client. The fixture sends empty form text (no credential) and
then verifies that both revoked access and refresh tokens are refused.

All four reviewed advisories must remain present exactly once. The existing session
advisory's complete description is frozen in `advisory-description.txt`; descriptions
for the additional advisories are hash-bound in
`advisory-description-hashes.json`. Both files are bound by `baseline.json`. Missing
findings or any description change require renewed review.
The target runtime must match every distribution and version in its lock plus
the application; only the venv bootstrap tool pip is exempt.
