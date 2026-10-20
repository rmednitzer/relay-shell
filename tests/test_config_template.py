"""The public deployment template must describe every server setting accurately."""

from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values

from relay_shell.config import Settings


def test_template_covers_settings_and_matches_defaults(clean_env: None) -> None:
    template = Path(__file__).resolve().parents[1] / ".env.example"
    # Parse data only; never source the template or load a private .env.
    values = dotenv_values(template, interpolate=False)
    prefix = str(Settings.model_config["env_prefix"])
    expected = {prefix + name.upper() for name in Settings.model_fields}
    # Edge variables belong to the installer/Caddy rather than Settings.
    edge = {
        "RELAY_SHELL_EDGE_DOMAIN",
        "RELAY_SHELL_EDGE_ACME_EMAIL",
        "RELAY_SHELL_EDGE_CLIENT_CIDRS",
        "RELAY_SHELL_EDGE_UPSTREAM",
        "RELAY_SHELL_EDGE_ACME_CA",
    }
    assert set(values) == expected | edge
    configured = Settings(
        _env_file=None,
        **{name: values[prefix + name.upper()] for name in Settings.model_fields},
    )
    assert configured.model_dump() == Settings(_env_file=None).model_dump()
