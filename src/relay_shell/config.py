"""Typed, environment-driven configuration.

All settings are read from ``RELAY_SHELL_*`` environment variables (and an optional
``.env``). Invalid values fail fast at startup rather than mid-run.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
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

    # Limits
    max_output: int = Field(default=65536, ge=1024)
    max_output_hard: int = Field(default=1_048_576, ge=4096)
    default_timeout: int = Field(default=60, ge=1)
    max_timeout: int = Field(default=900, ge=1)
    max_sessions: int = Field(default=64, ge=1, le=1024)
    session_idle_timeout: int = Field(default=1800, ge=10)
    session_buffer_bytes: int = Field(default=262_144, ge=4096)

    # Policy
    policy_mode: str = "open"
    policy_deny: str = ""
    policy_allow: str = ""

    # Audit
    audit_path: str = "/var/log/relay-shell/audit.jsonl"
    audit_stderr: bool = False
    audit_format: str = "jsonl"

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings instance."""
    return Settings()
