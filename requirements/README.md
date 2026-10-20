# Qualified dependency profiles

`runtime-py3.X.txt` contains only the complete application dependency closure.
`development-py3.X.txt` contains that same closure plus development and build tools.
The maintained profiles are CPython 3.12, 3.13 and 3.14 on the tested Linux runners.
Package compatibility ranges in pyproject.toml remain a separate library contract.

Install the selected profile with `python -m pip install --only-binary=:all:
--require-hashes -r requirements/development-py3.12.txt`, then install the checkout
with `python -m pip install --no-deps --no-build-isolation -e ".[dev]"` and run
`python -m pip check`. Use the matching interpreter, not a renamed lock file.
Binary-only installation fails when a qualified wheel is unavailable; it does
not silently compile a third-party source archive with unreviewed build tooling.

Regenerate each output with the uv command recorded in its header, from the
repository root. Review sources, selected versions, hashes, licensing and native
changes before acceptance. requirements.txt is the direct constraint input;
requirements-build.txt pins the build closure. Update all affected profiles
when either input changes. Renovate's pip-compile manager owns generated outputs.
The independent repository policy requires review of complete lock refreshes.

requirements-audit.txt is a separate complete audit-tool environment, generated
from requirements-audit.in. Do not install it into the subject environment and
mistake the resulting mixed environment for either locked profile.

A lock fixes selected package bytes; it does not establish provenance by itself,
absence of vulnerabilities, cross-platform qualification or reproducible native
compilation. CI exercises each selected profile. The package is installed after
dependencies with --no-deps; source builds require the separately locked backend.
