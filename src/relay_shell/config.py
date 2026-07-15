"""Typed, environment-driven configuration.

All settings are read from ``RELAY_SHELL_*`` environment variables (and an optional
``.env``). Invalid values fail fast at startup rather than mid-run.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "get_settings"]

_TRANSPORTS = {"stdio", "http"}
_POLICY_MODES = {"open", "guarded", "readonly"}
_KNOWN_HOSTS = {"strict", "accept-new", "ignore"}
_AUDIT_FORMATS = {"jsonl", "cef", "leef"}


class Settings(BaseSettings):
    """Effective server configuration. Immutable after load."""

    model_config = SettingsConfigDict(
        env_prefix="RELAY_SHELL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # Transport
    transport: str = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = Field(default=8080, ge=1, le=65535)

    # Limits. Every bound carries an explicit `le=` upper cap (CFG-1): without
    # one, an operator who env-sets an absurd value (e.g. a 1 TB output cap)
    # gets a clamp that never bites and a self-inflicted memory/DoS footgun.
    # The caps are deliberately generous — far above any real config — so they
    # reject only nonsense, never a legitimate large deployment.
    max_output: int = Field(default=65536, ge=1024, le=16_777_216)
    max_output_hard: int = Field(default=1_048_576, ge=4096, le=134_217_728)
    default_timeout: int = Field(default=60, ge=1, le=86_400)
    max_timeout: int = Field(default=900, ge=1, le=86_400)
    max_sessions: int = Field(default=64, ge=1, le=1024)
    max_forwards: int = Field(default=64, ge=1, le=1024)
    session_idle_timeout: int = Field(default=1800, ge=10, le=86_400)
    session_buffer_bytes: int = Field(default=262_144, ge=4096, le=16_777_216)

    # Policy
    policy_mode: str = "open"
    policy_deny: str = ""
    policy_allow: str = ""

    # Tier-3 confirmation broker (ADR 0009; opt-in, default off). When true, a
    # Tier-3 (IRREVERSIBLE) operation that passes the deny list and mode check
    # is not executed on first request: the runner returns a single-use,
    # TTL-bounded token and the caller must arm it via the `operation_confirm`
    # tool, then re-issue the exact same call. Default off keeps the record
    # byte-identical and the behavior unchanged. `confirm_ttl` bounds how long
    # a minted token stays valid before it must be re-planned.
    confirm_tier3: bool = False
    confirm_ttl: int = Field(default=120, ge=5, le=3600)

    # Audit
    audit_path: str = "/var/log/relay-shell/audit.jsonl"
    audit_stderr: bool = False
    audit_format: str = "jsonl"
    # Tamper-evident audit: when true, each record carries a `seq`, the
    # previous record's chain hash (`prev`), and its own `chain` hash so a
    # verifier can detect any insertion / deletion / reordering / edit of
    # the on-disk log (see docs/adr/0007-audit-hash-chain.md). Default off
    # keeps the record byte-identical to today. Only the `jsonl` format can
    # resume the chain across restarts, so chaining requires it.
    audit_chain: bool = False

    # Syscall-level audit channel (ADR 0006; opt-in, default off). When on,
    # locally-spawned children get a seccomp-bpf USER_NOTIF filter and the
    # supervisor appends one `syscall_notify` audit line per observed
    # syscall (execve, privilege/namespace/mount changes, write-opens). It
    # never blocks a syscall and only activates when the process holds
    # CAP_SYS_ADMIN (so set-uid/sudo behaviour is preserved verbatim);
    # otherwise it cleanly no-ops. `seccomp_notify_cap` bounds the per-call
    # event volume — beyond it, one `syscall_notify_overflow` line is written
    # and emission stops (the child still runs to completion).
    seccomp_notify: bool = False
    seccomp_notify_cap: int = Field(default=256, ge=1, le=65536)

    # SSH
    ssh_config: str = "~/.ssh/config"
    inventory: str = ""
    ssh_known_hosts: str = "accept-new"
    ssh_connect_timeout: int = Field(default=10, ge=1, le=120)
    ssh_keepalive: int = Field(default=30, ge=0, le=600)
    # Idle eviction for cached SSH connections. 0 disables the reaper
    # (matches the historical behavior). A non-zero value drops a cached
    # connection that has not been used for that many seconds the next
    # time the pool is consulted; see SshPool._sweep_conns.
    ssh_idle_timeout: int = Field(default=1800, ge=0, le=86400)

    # OAuth 2.1 (HTTP transport only)
    auth_enabled: bool = False
    auth_issuer: str = "https://localhost:8080"
    auth_state_dir: str = "/var/lib/relay-shell/oauth"
    auth_single_client: bool = True
    auth_access_ttl: int = Field(default=3600, ge=60)
    auth_refresh_ttl: int = Field(default=2_592_000, ge=300)
    auth_code_ttl: int = Field(default=300, ge=30)

    @field_validator("transport")
    @classmethod
    def _v_transport(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _TRANSPORTS:
            raise ValueError(f"transport must be one of {sorted(_TRANSPORTS)}")
        return v

    @field_validator("policy_mode")
    @classmethod
    def _v_policy(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _POLICY_MODES:
            raise ValueError(f"policy_mode must be one of {sorted(_POLICY_MODES)}")
        return v

    @field_validator("ssh_known_hosts")
    @classmethod
    def _v_known_hosts(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _KNOWN_HOSTS:
            raise ValueError(f"ssh_known_hosts must be one of {sorted(_KNOWN_HOSTS)}")
        return v

    @field_validator("audit_format")
    @classmethod
    def _v_audit_format(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _AUDIT_FORMATS:
            raise ValueError(f"audit_format must be one of {sorted(_AUDIT_FORMATS)}")
        return v

    @model_validator(mode="after")
    def _v_chain_requires_jsonl(self) -> Settings:
        # The hash chain is defined over the on-disk `jsonl` record and is
        # resumed across restarts by re-parsing the last line. CEF/LEEF are
        # SIEM-ingest shapes where the aggregator owns integrity, so refuse
        # the combination at startup rather than emit a chain that cannot be
        # resumed. Fails fast (per the module contract) instead of mid-run.
        if self.audit_chain and self.audit_format != "jsonl":
            raise ValueError("audit_chain=true requires audit_format=jsonl")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings instance."""
    return Settings()
