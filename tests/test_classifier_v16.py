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
        "docker compose --profile logs up -d",
        "docker compose up ps",
        "docker compose -p ps up",
        "kubectl --namespace=x delete pod y",
        "kubectl --insecure-skip-tls-verify delete pod",
        "systemctl -t service start x",
        "firewall-cmd --reload",
        "echo x >> authorized_keys",
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
        "docker compose --profile x logs",
        "docker compose --ansi never ps",
        "kubectl get pod delete",
        "kubectl get pods exec",
        "systemctl --user status stop",
        "systemctl --property=Id show stop",
        "firewall-cmd --permanent --get-zones",
        "firewall-cmd --permanent --list-all",
        "firewall-cmd --query-port=80/tcp",
        "echo x > ./backup_authorized_keys",
        "echo x > /tmp/notauthorized_keys",
        "echo x > authorized_keys.bak",
        "echo x > ~/.bashrc.bak",
        "echo timeout 5 reboot",
        "man nice -n 10 reboot",
        "grep redis-cli FLUSHDB docs",
        "echo redis-cli FLUSHALL",
        "printf '%s' 'r\\\nm -rf /srv'",
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
        "echo 'sudo -n touch /root/pwn' | sh",
        "echo 'sudo -n touch /root/pwn' | bash -s",
        "printf 'sudo id\\n' | /bin/sh",
        "grep -h sudo cmds.txt | xargs -I{} sh -c {}",
        'echo sudo id > /tmp/x; sh /tmp/x; eval "$(echo sudo id)"',
        "$(echo sudo reboot)",
        "`echo sudo -n touch /x`",
        "echo sudo -n id | sudo sh",
        "eval 'echo sudo id'",
    ],
)
def test_a_real_privilege_wrapper_still_escalates(command: str) -> None:
    assert tier(command) >= Tier.STATEFUL


def test_wrappers_with_arguments_need_a_command_boundary() -> None:
    assert tier("FOO=1 timeout 5 reboot") is Tier.IRREVERSIBLE
    assert tier("echo hi; ionice -c 2 shutdown now") is Tier.IRREVERSIBLE
    assert tier("echo ok && /usr/bin/timeout 5 reboot") is Tier.IRREVERSIBLE


def test_line_continuation_is_removed_before_matching() -> None:
    """`\\<newline>` is deleted by the shell: a destructive word cannot hide behind it."""
    assert tier("echo hi \\\nreboot") is Tier.REVERSIBLE  # joined: `reboot` is an argument
    assert tier("echo hi\nreboot") is Tier.IRREVERSIBLE  # a real second command
    # Inside single quotes the pair is literal text, so it cannot build a command.
    assert tier("printf '%s' 'r\\\nm -rf /srv'") is Tier.REVERSIBLE
    # Double quotes still delete it, and an unbalanced quote falls back to deleting.
    assert tier('echo "x" ; rm \\\n-rf /srv') is Tier.IRREVERSIBLE
    assert tier("echo it's; rm \\\n-rf /srv") is Tier.IRREVERSIBLE
    # An escaped backslash before a newline is not a continuation.
    assert tier("echo hi \\\\\nreboot") is Tier.IRREVERSIBLE


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
        "'a\\\n" * 20_000,
        '"a\\\n' * 20_000,
        '"' * 50_000,
        '\\"' * 30_000,
        "grep " * 8000,
        "| " * 20_000,
        "echo sudo " * 8000,
        "$( " * 20_000,
        "echo ;" * 10_000,
    ],
)
def test_new_patterns_are_linear_on_adversarial_input(payload: str) -> None:
    started = time.perf_counter()
    classify("shell_exec", payload)
    assert time.perf_counter() - started < 2.0
