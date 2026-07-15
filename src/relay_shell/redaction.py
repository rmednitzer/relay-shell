"""Secret redaction for the audit trail.

Audited arguments are scrubbed before they are written so that the audit log
(which is meant to be shipped off-host) never becomes a secret store. The
output *body* is never logged at all (only its hash); this module covers the
*argument* surface, where a caller might pass a token or key inline.

Scope is deliberately bounded. The patterns target well-defined syntaxes:
PEM blocks, ``Authorization`` headers, ``Bearer``/``key=value`` pairs
(including the JSON-quoted-key shape ``"password": "x"`` — RED-6),
long-name CLI flags - matching either a double dash (``--password=...``,
``--token VALUE``) or the single-dash long-name style some Go-flavored
tools use (``-token=foo``, ``-password VALUE``), including quoted values
and escape-aware backslash-space - URL-embedded credentials, a few
cloud-provider assignment forms (AWS ``*_SECRET_ACCESS_KEY=``, Azure
connection-string ``AccountKey=``/``SharedAccessKey=`` and SAS ``sig=``),
and a handful of provider token shapes. Short-form single-letter flags like ``-p<value>``
are redacted **only** when a MySQL-family CLI (``mysql``, ``mariadb-*``,
``mycli``) appears in the same argument string: ``-p`` is overloaded
across SSH (``-p22``), nmap (``-p1-1000``), and other tools, so the
MySQL-family gate avoids over-redacting unrelated arguments while still
covering the common ``mysql -psecret`` shape. Operators putting DB
passwords on the command line should still prefer ``--password=...``,
the interactive ``-p`` (no value), or ``~/.my.cnf`` instead.

Beyond those syntaxes, a set of *structurally anchored* provider token
shapes is collapsed wherever they appear - a bare token in a JSON body or
a log line, not just behind a known prefix. These track the canonical
secret-scanning rulesets (gitleaks / GitHub secret scanning): GitHub PAT
and ``gh[pousr]_`` tokens, OpenAI ``sk-`` (including the
``sk-proj-``/``sk-svcacct-``/``sk-admin-`` prefixes), AWS access key ids,
Slack ``xox*`` tokens and incoming-webhook URLs, Google API keys (``AIza``)
and OAuth tokens (``ya29.``), Stripe ``sk_``/``rk_`` keys, GitLab ``glpat-``
tokens, npm ``npm_`` tokens, PyPI ``pypi-`` upload tokens, Anthropic
``sk-ant-`` keys, HuggingFace ``hf_`` tokens, and JWTs. The anchor is the
prefix and a length floor, never the value's character class, so the rule
survives a provider rotating its alphabet.

The compiled regex tables live in :mod:`relay_shell.patterns` so a security
reviewer can audit "added a pattern" as a one-file diff.
"""

from __future__ import annotations

from typing import Any

from . import patterns

__all__ = ["redact", "redact_args"]


def redact(text: str) -> str:
    """Replace secret-looking spans in ``text`` with a placeholder."""
    placeholder = patterns.REDACTION_PLACEHOLDER
    out = patterns.URL_CREDS_PATTERN.sub(f"://{placeholder}@", text)
    for pat, repl in patterns.REDACTION_PREFIX_PATTERNS:
        out = pat.sub(repl, out)
    for pat in patterns.REDACTION_PATTERNS:
        out = pat.sub(placeholder, out)
    if patterns.MYSQL_FAMILY_CLI_PATTERN.search(out):
        out = patterns.MYSQL_COMPACT_PASSWORD_PATTERN.sub(
            lambda m: f"{m.group(1)}{placeholder}", out
        )
    return out


# P1 (2026-07-15 perf pass): `_scrub_str` keeps only the first `max_len` chars
# of the redacted result, so a secret that survives truncation must *start*
# within the first `max_len` chars. Scanning only `max_len + margin` — instead
# of running the ~two-dozen-regex table over a multi-MB `command`/`stdin`/
# `env_json` argument synchronously on `Relay.run`'s hot path — removes the
# dominant per-call CPU cost. Correctness rests on the redaction patterns being
# *truncation-safe*: a secret that begins in the kept prefix must still be
# collapsed when the scan window severs its far end. Two shapes exist:
#   1. Greedy-run patterns (Bearer, `key=value`, provider tokens) match whatever
#      is visible, so a truncated secret still collapses on its head.
#   2. Delimiter-terminated patterns must be bounded or have an end fallback:
#      the PEM block bounds its body to 8 KB (RED-2, < margin); the quoted
#      CLI-flag value and the Authorization header value each fall back to an
#      end-of-line branch (RED-8 / the `$` alternative) so a truncated quoted
#      value still collapses instead of leaking its post-space tail.
# The dropped tail is truncated out of the audit record regardless, so bounding
# the scan cannot leak a secret the full-string scan would have caught. The
# margin sits comfortably above the 8 KB PEM bound (the one span whose match
# length the truncation-safety of a delimiter pattern still depends on).
_REDACT_SCAN_MARGIN = 16384


def _scrub_str(text: str, max_len: int) -> str:
    scanned = text[: max_len + _REDACT_SCAN_MARGIN]
    red = redact(scanned)
    overflow = len(red) - max_len  # redacted chars beyond the cap (scanned part)
    tail = len(text) - len(scanned)  # unscanned original chars (all dropped)
    if overflow > 0 or tail > 0:
        # For any input up to the scan window (every realistic argument) this is
        # byte-identical to the pre-P1 output; beyond it the count also reflects
        # the unscanned tail so the "+N" hint is never misleadingly small.
        red = red[:max_len] + f"...(+{max(overflow, 0) + tail})"
    return red


def _scrub(value: Any, max_len: int) -> Any:
    if isinstance(value, bytes):
        # RED-4: a bytes argument would otherwise fall through unredacted via
        # the `return value` below. No current wrapper passes bytes in audit
        # args, but decode defensively (lossy, never raises) so a future caller
        # cannot smuggle a secret past redaction as raw bytes.
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return _scrub_str(value, max_len)
    if isinstance(value, dict):
        # RED-5: scrub keys too, not only values — a nested, caller-supplied
        # dict (e.g. a parsed JSON body passed as an argument) could carry a
        # secret in a key, not just a value.
        return {
            (_scrub_str(k, max_len) if isinstance(k, str) else k): _scrub(v, max_len)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(v, max_len) for v in value]
    return value


def redact_args(args: dict[str, Any], max_len: int = 500) -> dict[str, Any]:
    """Return a redacted, length-bounded copy of an audit-argument mapping."""
    return {k: _scrub(v, max_len) for k, v in args.items()}
