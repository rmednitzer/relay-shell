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

The baseline also stores raw OAuth credentials. Tests generate temporary fixture
grants, verify their migration to hashed storage and verify that current code
refuses legacy grants lacking resource binding. Reauthorization is required.
Rollback preserves the accepted audit tail and clears grants/codes before the old
service starts; snapshot tokens must not silently become usable again. This does
not preserve every newer security policy or make the old release suitable for an
operational downgrade. No operational hosts, clients, credentials or TLS are used.
