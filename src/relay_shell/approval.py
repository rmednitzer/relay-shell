"""Operator approval of Tier-3 confirmations with SSH signatures (ADR 0015).

With ``RELAY_SHELL_CONFIRM_APPROVAL=signature`` a Tier-3 confirmation token can
be armed only with an SSHSIG signature, made outside the relay with a key the
service account does not hold, over a one-line challenge that names the
operation. The model can relay the challenge and the signature, but it cannot
produce the signature, and a signature over one operation does not arm another.

The relay's own account (and anything it can ``sudo``) is not a trustworthy
approver: ``shell_exec`` runs as that account, so any approval the host can
grant to itself (a CLI verb, a marker file) is one the model can grant too.
A signature made off-host by the operator is the smallest change that puts a
human-held credential in the loop. Verification uses ``asyncssh``'s SSHSIG
implementation; nothing here implements cryptography.

What this does not cover: a model that can change the allowed-signers file and
restart the service (the service account has root on a privileged deployment)
can substitute its own key. The file is read once at startup, its key
fingerprints are listed in ``server_info``, and a change needs a restart, so
the substitution is visible, but it is not prevented (ADR 0002 posture).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh
from asyncssh.sshsig import SSHAllowedSignersEntry, import_allowed_signers

from .util import sha256_hex

__all__ = [
    "CHALLENGE_PREFIX",
    "MAX_SIGNATURE_CHARS",
    "NAMESPACE",
    "SignatureVerifier",
    "Signer",
    "build_challenge",
    "default_server_name",
    "signature_namespace",
    "token_fingerprint",
]

# The SSHSIG namespace an approval must be made in (`ssh-keygen -Y sign -n ...`).
# A signature made for another purpose (git commits use "git", files "file") is
# refused even when the key is an allowed signer.
NAMESPACE = "relay-shell-confirm"
CHALLENGE_PREFIX = "relay-shell-confirm v1 "

# An armored ed25519/ecdsa/rsa-4096 SSHSIG is under 2 KiB; the cap bounds the
# work done on caller-supplied input before any verification.
MAX_SIGNATURE_CHARS = 16_384
# Bounds the rendered argument summary inside the one-line challenge. The full
# operation is still bound through `op` (the broker's operation hash).
_MAX_ARGS_CHARS = 4096
_MAX_PRINCIPALS = 32
_SSHSIG_MAGIC = b"SSHSIG"
_WILDCARD_CHARS = frozenset("*?!")


def build_challenge(
    *,
    token: str,
    tool: str,
    args: Mapping[str, Any],
    op_hash: str,
    expires: str,
    server: str,
) -> str:
    """The single line the operator signs to approve one planned Tier-3 call.

    ``args`` must already be redacted (the audit view), so no secret reaches
    the operator's terminal or the signed file. ``op_hash`` is the broker's
    binding over the un-redacted command and every argument, so a truncated or
    redacted summary still identifies exactly one operation. ASCII-only JSON
    on one line keeps the signed bytes stable across copy and paste.
    """
    rendered = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    if len(rendered) > _MAX_ARGS_CHARS:
        rendered = rendered[:_MAX_ARGS_CHARS] + "...[truncated; bound by op]"
    body = {
        "args": rendered,
        "exp": expires,
        "id": token_fingerprint(token),
        "op": op_hash,
        "server": server,
        "tool": tool,
    }
    return CHALLENGE_PREFIX + json.dumps(body, sort_keys=True, separators=(",", ":"))


def token_fingerprint(token: str) -> str:
    """The 12-hex token fingerprint the audit record uses for ``operation_confirm``."""
    return sha256_hex(token)[:12]


def signature_namespace(signature: str) -> str | None:
    """The namespace inside an armored SSHSIG, or ``None`` if it is malformed.

    ``asyncssh.validate_sshsig`` checks a namespace only when the allowed-signers
    entry restricts one, so the namespace is checked here as well.
    """
    lines = [ln.strip() for ln in signature.strip().splitlines()]
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN SSH SIGNATURE-----"
        or lines[-1] != "-----END SSH SIGNATURE-----"
    ):
        return None
    try:
        blob = base64.b64decode("".join(lines[1:-1]), validate=True)
    except (binascii.Error, ValueError):
        return None
    if blob[:6] != _SSHSIG_MAGIC or len(blob) < 10:
        return None
    pos = 10  # magic (6) + version (uint32)
    for field in range(2):  # public key, then namespace
        if pos + 4 > len(blob):
            return None
        (length,) = struct.unpack(">I", blob[pos : pos + 4])
        pos += 4
        if pos + length > len(blob):
            return None
        if field == 1:
            try:
                return blob[pos : pos + length].decode("utf-8")
            except UnicodeDecodeError:
                return None
        pos += length
    return None  # pragma: no cover - the loop always returns


@dataclass(frozen=True)
class Signer:
    principal: str
    fingerprint: str


class SignatureVerifier:
    """Allowed signers for confirmation approvals, loaded once at startup.

    Fails fast on anything ambiguous rather than skipping it: an unparsable
    line, a wildcard or negated principal, a ``cert-authority`` entry, a file
    that group or other can write, or an empty file. (``asyncssh`` on its own
    silently skips lines it cannot parse.)
    """

    def __init__(self, path: str) -> None:
        if not path:
            raise ValueError(
                "RELAY_SHELL_CONFIRM_APPROVAL=signature needs RELAY_SHELL_CONFIRM_ALLOWED_SIGNERS"
            )
        file = Path(path).expanduser()
        try:
            st = file.stat()
        except OSError as exc:
            raise ValueError(f"confirm allowed signers {file}: {exc.strerror}") from None
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"confirm allowed signers {file}: not a regular file")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(
                f"confirm allowed signers {file}: writable by group or other; "
                "make it root-owned and 0644 or stricter"
            )
        text = file.read_text(encoding="utf-8")
        principals: list[str] = []
        signers: list[Signer] = []
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = SSHAllowedSignersEntry(line)
            except (ValueError, asyncssh.KeyImportError) as exc:
                raise ValueError(f"confirm allowed signers {file}:{number}: {exc}") from None
            if "cert-authority" in entry.options:
                raise ValueError(
                    f"confirm allowed signers {file}:{number}: cert-authority entries "
                    "are not supported; list the operator keys directly"
                )
            names = line.split(None, 1)[0].split(",")
            if any(not n or _WILDCARD_CHARS & set(n) for n in names):
                raise ValueError(
                    f"confirm allowed signers {file}:{number}: principals must be plain "
                    "names (no wildcards or negation)"
                )
            fingerprint = entry.key.get_fingerprint("sha256")
            for name in names:
                if name not in principals:
                    principals.append(name)
                signers.append(Signer(principal=name, fingerprint=fingerprint))
        if not principals:
            raise ValueError(f"confirm allowed signers {file}: no entries")
        if len(principals) > _MAX_PRINCIPALS:
            raise ValueError(
                f"confirm allowed signers {file}: more than {_MAX_PRINCIPALS} principals"
            )
        self.path = str(file)
        self._allowed = import_allowed_signers(text)
        self._principals = tuple(principals)
        self.signers = tuple(signers)

    def describe(self) -> list[dict[str, str]]:
        """Principals and key fingerprints, for ``server_info``."""
        return [{"principal": s.principal, "fingerprint": s.fingerprint} for s in self.signers]

    def verify(self, challenge: str, signature: str) -> str | None:
        """The principal whose key signed ``challenge`` in :data:`NAMESPACE`, else ``None``.

        The signed file may or may not end in a newline (LF or CRLF) depending
        on how it was saved; all three encodings of the same server-issued line
        are accepted, nothing else.
        """
        if not signature or len(signature) > MAX_SIGNATURE_CHARS:
            return None
        if signature_namespace(signature) != NAMESPACE:
            return None
        sig = signature.strip().encode("ascii", "replace") + b"\n"
        for data in (challenge, challenge + "\n", challenge + "\r\n"):
            payload = data.encode("utf-8")
            for principal in self._principals:
                try:
                    if asyncssh.validate_sshsig(payload, sig, principal, self._allowed):
                        return principal
                except Exception:  # noqa: BLE001 - caller-supplied bytes must never raise
                    return None
        return None


def default_server_name() -> str:
    """The ``server`` field of a challenge: this host's name."""
    return os.uname().nodename
