from configparser import ConfigParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DROPIN = ROOT / "deploy/systemd/relay-shell.service.d/hardening.conf"


def service_settings():
    parser = ConfigParser(interpolation=None, strict=False)
    parser.read(DROPIN)
    return parser["Service"]


@pytest.mark.parametrize(
    "directive",
    [
        "NoNewPrivileges",
        "PrivateTmp",
        "PrivateDevices",
        "PrivateUsers",
        "PrivateMounts",
        "PrivateNetwork",
        "ProtectSystem",
        "ProtectHome",
        "ProtectHostname",
        "ProtectClock",
        "ProtectKernelTunables",
        "ProtectKernelLogs",
        "ProtectKernelModules",
        "ProtectControlGroups",
        "RestrictRealtime",
        "LockPersonality",
        "RestrictNamespaces",
    ],
)
def test_administrator_commands_are_not_silently_confined(directive):
    assert service_settings()[directive] == "no"


def test_full_bounding_set_and_no_unit_syscall_filter():
    settings = service_settings()
    assert settings["CapabilityBoundingSet"] == "~"
    assert settings["SystemCallFilter"] == ""


def test_resource_and_file_creation_controls_remain():
    settings = service_settings()
    expected = {
        "MemoryHigh": "768M",
        "MemoryMax": "1024M",
        "CPUQuota": "80%",
        "TasksMax": "128",
        "LimitNOFILE": "8192",
        "UMask": "0077",
    }
    assert all(settings[key] == value for key, value in expected.items())


def test_daemon_identity_and_policy_are_not_replaced():
    parser = ConfigParser(interpolation=None, strict=False)
    parser.read(ROOT / "deploy/systemd/relay-shell.service")
    assert parser["Service"]["User"] == "relay-shell"
    assert parser["Service"]["Group"] == "relay-shell"
    text = DROPIN.read_text()
    assert "RELAY_SHELL_POLICY_MODE=" not in text
    assert "RELAY_SHELL_AUDIT_" not in text
