"""A14-C9: classifier tuning (PATTERNS_VERSION 16). Heuristic, not containment (ADR 0003).

Each group pairs the commands that must now escalate with near-misses that must not.
"""

from __future__ import annotations

import time

import pytest

from relay_shell.policy import Tier, classify


def tier(command: str) -> Tier:
    return classify("shell_exec", command)


@pytest.mark.parametrize(
    "command",
    [
        "rm \\\n-rf /srv",
        "r\\\nm -rf /srv",
        "sudo -u root reboot",
        "sudo -E -u root shutdown now",
        "doas -u root reboot",
        "nice -n 10 reboot",
        "ionice -c 2 -n 7 shutdown now",
        "timeout 5 reboot",
        "timeout -k 3 10s poweroff",
        "setsid halt",
        "redis-cli FLUSHALL",
        "redis-cli -h cache -a x flushdb",
    ],
)
def test_wrapped_or_continued_destructive_commands_are_tier3(command: str) -> None:
    assert tier(command) is Tier.IRREVERSIBLE


@pytest.mark.parametrize(
    "command",
    [
        "systemctl start nginx",
        "systemctl enable --now nginx",
        "systemctl --user restart app",
        "systemctl -H host stop app",
        "systemctl reload nginx",
        "systemctl daemon-reload",
        "service nginx start",
        "useradd bob",
        "usermod -aG docker bob",
        "groupadd ops",
        "chpasswd < users.txt",
        "iptables -A INPUT -j DROP",
        "iptables -t nat -I PREROUTING 1 -j X",
        "ip6tables -D INPUT 3",
        "iptables-restore < rules.v4",
        "nft add rule inet f input drop",
        "firewall-cmd --permanent --add-port=80/tcp",
        "kubectl exec -it pod -- sh",
        "kubectl -n prod drain node1 --ignore-daemonsets",
        "kubectl --context prod delete pod x",
        "kubectl cordon node1",
        "kubectl patch deploy x -p {}",
        "kubectl edit cm settings",
        "redis-cli shutdown nosave",
        "redis-cli config set save ''",
        "echo ssh-rsa AAA >> ~/.ssh/authorized_keys",
        "cat key | tee -a $HOME/.ssh/authorized_keys",
        "echo 'alias x=y' >> ~/.bashrc",
        "echo x >> .bashrc",
        "echo x > /root/.profile",
        "echo 'u ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/u",
        "echo x > /usr/local/bin/tool",
        "printf x | tee /var/www/html/index.html",
        "docker compose up -d",
        "docker-compose down",
        "docker compose -f logs.yml up",
        "crontab -e",
        "crontab mycron",
    ],
)
def test_state_changes_that_were_tier1_are_now_tier2(command: str) -> None:
    assert tier(command) >= Tier.STATEFUL


@pytest.mark.parametrize(
    "command",
    [
        "systemctl status nginx",
        "systemctl is-enabled nginx",
        "systemctl list-units --type=service",
        "systemctl cat start.service",
        "man useradd",
        "grep useradd /var/log/auth.log",
        "iptables -L -n",
        "iptables -t nat -S",
        "nft list ruleset",
        "kubectl get pods -n prod",
        "kubectl logs job/create-db",
        "kubectl get cm drain-config",
        "kubectl describe node exec-node",
        "redis-cli get key",
        "redis-cli info",
        "echo hi > /tmp/out.txt",
        "ls 2>/dev/null",
        "echo ok > ./out.txt",
        "cat /etc/hosts > /tmp/hosts.copy",
        "cat ~/.ssh/known_hosts | wc -l",
        "docker compose ps",
        "docker compose logs -f web",
        "docker-compose -f a.yml config",
        "docker compose version",
    ],
)
def test_near_misses_stay_tier1(command: str) -> None:
    assert tier(command) is Tier.REVERSIBLE


@pytest.mark.parametrize(
    "command",
    [
        "crontab -l",
        "crontab -u bob -l",
        "grep sudo /var/log/auth.log",
        "grep -ri 'sudo ' /var/log | head",
        "man sudo",
        "which sudo",
        "echo sudo is required",
        "journalctl -t sudo --since today",
    ],
)
def test_read_only_commands_no_longer_over_classify(command: str) -> None:
    assert tier(command) is Tier.REVERSIBLE


@pytest.mark.parametrize(
    "command",
    [
        "sudo ls",
        "grep x file | sudo tee /y",
        "echo ok; sudo systemctl stop x",
        "grep x $(sudo cat /etc/shadow)",
        "ssh host sudo cp a /usr/bin/a",
        "printf '%s' \"$(sudo cat k)\"",
    ],
)
def test_a_real_privilege_wrapper_still_escalates(command: str) -> None:
    assert tier(command) >= Tier.STATEFUL


def test_line_continuation_is_removed_before_matching() -> None:
    """`\\<newline>` is deleted by the shell: a destructive word cannot hide behind it."""
    assert tier("echo hi \\\nreboot") is Tier.REVERSIBLE  # joined: `reboot` is an argument
    assert tier("echo hi\nreboot") is Tier.IRREVERSIBLE  # a real second command


def test_patterns_version_16_or_later() -> None:
    from relay_shell import patterns

    assert int(patterns.PATTERNS_VERSION) >= 16


@pytest.mark.parametrize(
    "payload",
    [
        "kubectl " * 6000,
        "systemctl --user " * 4000,
        "sudo -u " * 6000,
        "nice " * 8000,
        "timeout 5 " * 6000,
        "docker compose " * 4000,
        "redis-cli " * 6000,
        "iptables -t x " * 4000,
        "> " + "a" * 100_000,
        ">>" + "/a" * 40_000,
        "tee " + "-a " * 20_000,
        "crontab " * 8000,
        "\\\n" * 20_000,
        "grep " * 8000,
        "echo ;" * 10_000,
    ],
)
def test_new_patterns_are_linear_on_adversarial_input(payload: str) -> None:
    started = time.perf_counter()
    classify("shell_exec", payload)
    assert time.perf_counter() - started < 2.0
