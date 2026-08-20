"""Execution: what it refuses, what it verifies, and what it undoes."""

import pytest

from app.execute.base import APPLIED, LOGGED, REFUSED, ROLLBACK_FAILED, ROLLED_BACK
from app.execute.device import DeviceExecutor
from app.execute.dryrun import DryRunExecutor
from app.execute.guard import check, is_policy_command
from app.execute.live import _same_rule
from app.execute.session import FORBIDDEN, ConfigSession, UnsafeCommand
from app.firewall.policy import AclRule, parse_acl_command

COMMAND = "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"
ROLLBACK = f"no {COMMAND}"

FLOWS = [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}]


def action(**overrides) -> dict:
    base = {
        "device": "FW_Edge",
        "command": COMMAND,
        "rollback": ROLLBACK,
        "position": 39,
        "verified": True,
        "rollback_verified": True,
    }
    base.update(overrides)
    return base


class FakeDevice:
    """A firewall whose policy changes when configuration is sent to it.

    Close enough to a real device for the parts that matter here: it applies
    lines, removes them on `no`, and can be told to ignore a command the way an
    appliance silently does when a line is rejected.
    """

    def __init__(self, *, deaf: bool = False, refuse_rollback: bool = False) -> None:
        self.rules = [
            AclRule(
                line=40,
                action="deny",
                proto="tcp",
                src="10.10.1.0/24",
                dst="10.20.1.0/24",
                port=443,
                rule_id="ACL-DMZ-47",
            )
        ]
        self.deaf = deaf
        self.refuse_rollback = refuse_rollback
        self.sent: list[str] = []
        self.refreshed = 0
        self.closed = 0

    # FirewallStore surface used by verification
    def describe(self) -> str:
        return "fake device"

    def refresh(self, device_id: str) -> None:
        self.refreshed += 1

    def acl_policy(self, device_id: str) -> list[AclRule]:
        return sorted(self.rules, key=lambda rule: rule.line)

    # The write path
    def close(self) -> None:
        self.closed += 1

    def send_config(self, commands: list[str]) -> str:
        for command in commands:
            self.sent.append(command)
            if command.lower().startswith("no "):
                if self.refuse_rollback:
                    raise RuntimeError("connection lost mid-rollback")
                target = parse_acl_command(command[3:])
                self.rules = [
                    rule
                    for rule in self.rules
                    if not (target and (rule.src, rule.dst, rule.port) == (target.src, target.dst, target.port)
                            and rule.action == target.action)
                ]
                continue
            if self.deaf:
                continue
            rule = parse_acl_command(command)
            if rule is not None:
                rule.line = 39
                self.rules.append(rule)
        return "\n".join(commands)


def executor_for(device: FakeDevice, **kwargs) -> DeviceExecutor:
    return DeviceExecutor(
        device, lambda _device_id: device, devices={"FW_Edge"}, **kwargs
    )


def test_dry_run_is_the_default_and_touches_nothing():
    result = DryRunExecutor().apply([action()], FLOWS)
    assert result.state == LOGGED
    assert result.touched_device is False
    assert "nothing was sent" in " ".join(result.lines)


def test_only_acl_lines_this_system_can_model_are_executable():
    assert is_policy_command(COMMAND) is True
    assert is_policy_command(ROLLBACK) is True
    assert is_policy_command("reload in 5") is False
    assert is_policy_command("") is False


@pytest.mark.parametrize(
    "override,expected",
    [
        ({"verified": False}, "did not pass simulation"),
        ({"rollback_verified": False}, "no verified rollback"),
        ({"device": "FW_Other"}, "not in EXECUTION_DEVICES"),
        ({"command": "reload"}, "not an ACL line"),
    ],
)
def test_the_guard_names_every_reason_it_refuses(override, expected):
    result = check([action(**override)], FLOWS, {"FW_Edge"})
    assert result.ok is False
    assert any(expected in reason for reason in result.reasons)


def test_a_change_without_evidence_cannot_be_verified_so_is_refused():
    result = check([action()], [], {"FW_Edge"})
    assert result.ok is False
    assert any("no denied-flow evidence" in reason for reason in result.reasons)


def test_a_refused_change_never_reaches_the_device():
    device = FakeDevice()
    result = executor_for(device).apply([action(verified=False)], FLOWS)
    assert result.state == REFUSED
    assert device.sent == []


def test_a_good_change_is_applied_and_confirmed_against_the_device():
    device = FakeDevice()
    result = executor_for(device).apply([action()], FLOWS)

    assert result.state == APPLIED
    assert device.sent == [COMMAND]
    # The confirmation came from a fresh read, not from the simulation.
    assert device.refreshed >= 1
    assert any("LIVE PASS" in line for line in result.verification)
    # A device has a finite number of VTY lines.
    assert device.closed == 1


def test_the_session_is_released_even_when_everything_goes_wrong():
    device = FakeDevice(deaf=True, refuse_rollback=True)
    executor_for(device).apply([action()], FLOWS)
    assert device.closed == 1


def test_one_session_serves_the_change_and_its_reversal():
    device = FakeDevice(deaf=True)
    executor_for(device).apply([action()], FLOWS)
    assert device.closed == 1  # not reopened to roll back


def test_a_device_that_accepts_the_command_but_does_nothing_is_rolled_back():
    """The failure mode that makes post-change verification worth having."""
    device = FakeDevice(deaf=True)
    result = executor_for(device).apply([action()], FLOWS)

    assert result.state == ROLLED_BACK
    assert device.sent == [COMMAND, ROLLBACK]
    assert any("LIVE FAIL" in line for line in result.verification)
    assert any("back in its previous state" in line for line in result.lines)


def test_a_failed_rollback_is_a_loud_terminal_state():
    device = FakeDevice(deaf=True, refuse_rollback=True)
    result = executor_for(device).apply([action()], FLOWS)

    assert result.state == ROLLBACK_FAILED
    assert result.needs_attention is True
    assert "Intervene by hand now" in " ".join(result.lines)


def test_rollback_can_be_disabled_and_then_says_so_loudly():
    device = FakeDevice(deaf=True)
    result = executor_for(device, auto_rollback=False).apply([action()], FLOWS)

    assert result.state == ROLLBACK_FAILED
    assert device.sent == [COMMAND]
    assert "AUTO ROLLBACK IS DISABLED" in " ".join(result.lines)


def test_a_failure_while_sending_triggers_the_same_reversal():
    class Broken(FakeDevice):
        def send_config(self, commands):
            if not commands[0].lower().startswith("no "):
                raise RuntimeError("session dropped")
            return super().send_config(commands)

    device = Broken()
    result = executor_for(device).apply([action()], FLOWS)
    assert result.state in (ROLLED_BACK, ROLLBACK_FAILED)
    assert any("session dropped" in step.error for step in result.steps if step.error)


@pytest.mark.parametrize("word", ["reload", "write erase", "copy running-config tftp:"])
def test_the_session_screens_destructive_commands_whatever_the_caller_says(word):
    with pytest.raises(UnsafeCommand):
        ConfigSession.screen([f"{word} something"])


def test_execution_stays_off_until_two_separate_switches_are_set(monkeypatch):
    """Enabling the feature and choosing the hardware are different decisions."""
    from app import execute
    from app.config import settings

    monkeypatch.setattr(settings, "firewall_backend", "cisco_asa")

    monkeypatch.setattr(settings, "execution_enabled", False)
    monkeypatch.setattr(settings, "execution_devices", "FW_Edge")
    assert isinstance(execute.make_executor(FakeDevice()), DryRunExecutor)

    monkeypatch.setattr(settings, "execution_enabled", True)
    monkeypatch.setattr(settings, "execution_devices", "")
    assert isinstance(execute.make_executor(FakeDevice()), DryRunExecutor)


def test_execution_against_fixtures_is_refused_as_meaningless(monkeypatch):
    from app import execute
    from app.config import settings

    monkeypatch.setattr(settings, "execution_enabled", True)
    monkeypatch.setattr(settings, "execution_devices", "FW_Edge")
    monkeypatch.setattr(settings, "firewall_backend", "mock")
    assert isinstance(execute.make_executor(FakeDevice()), DryRunExecutor)


def test_the_screen_covers_the_obvious_ways_to_break_a_network():
    assert "reload" in FORBIDDEN
    assert "shutdown" in FORBIDDEN
    ConfigSession.screen([COMMAND, ROLLBACK])  # a policy change passes


def test_srlinux_may_only_delete_one_numbered_ipv4_acl_entry():
    ConfigSession.screen(
        ["delete / acl acl-filter DMZ_TO_TRUST type ipv4 entry 30"]
    )
    with pytest.raises(UnsafeCommand):
        ConfigSession.screen(["delete / interface ethernet-1/1"])


def test_srlinux_configuration_is_committed_before_live_readback():
    class Candidate:
        def __init__(self):
            self.commits = 0

        def send_config_set(self, commands, read_timeout):
            return "candidate changed\n"

        def commit(self):
            self.commits += 1
            return "committed\n"

    connection = Candidate()
    session = ConfigSession(
        "192.0.2.30",
        "admin",
        "password",
        device_type="nokia_srl",
    )
    session._conn = connection

    output = session.send_config(
        ["set / acl acl-filter TEST type ipv4 entry 10 action accept"]
    )

    assert connection.commits == 1
    assert output == "candidate changed\ncommitted\n"


def test_live_verification_treats_a_host_and_its_32_prefix_as_the_same_rule():
    expected = parse_acl_command(COMMAND)
    assert expected is not None
    read_back = AclRule(
        line=30,
        action="permit",
        proto="tcp",
        src="10.10.1.10/32",
        dst="10.20.1.50/32",
        port=443,
    )
    assert _same_rule(read_back, expected)
