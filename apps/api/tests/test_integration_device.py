"""Against a device-shaped SSH server, driven by the real client.

Every other test in this suite replaces the transport. These do not: Netmiko
negotiates a real session, reads its own echo, detects a prompt, disables
paging and sends configuration to something whose state actually changes. That
is the half of the device code fixtures cannot reach.

Skipped unless the emulator is running:

    scripts/lab_device_test.sh

which starts the emulator, runs these tests with the project's interpreter and
takes it down again. Doing it by hand needs both halves: the `devices` extra
installed, and the emulator listening. Missing either one skips rather than
fails, so a run that tested nothing still looks green.
"""

import os
import socket

import pytest

from app.execute.device import DeviceExecutor
from app.execute.render import device_commands
from app.execute.session import ConfigSession
from app.firewall.base import FlowQuery
from app.firewall.ssh import ReadOnlyViolation

pytest.importorskip(
    "netmiko",
    reason="netmiko is missing: install the devices extra, and check you are not "
    "running a system pytest instead of the project's interpreter",
)

from app.firewall.asa import CiscoAsaFirewall  # noqa: E402 - needs the guard above

HOST = os.environ.get("FAKE_ASA_HOST", "127.0.0.1")
PORT = int(os.environ.get("FAKE_ASA_PORT", "2222"))
USERNAME = os.environ.get("FAKE_ASA_USER", "netops")
PASSWORD = os.environ.get("FAKE_ASA_PASSWORD", "zeronode")

FLOW = FlowQuery(
    source_device="Web_App",
    source_ip="10.10.1.10",
    target_device="DB_Primary",
    target_ip="10.20.1.50",
    port=443,
)
FLOWS = [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}]
COMMAND = "access-list DMZ_TO_TRUST extended permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"


def reachable() -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.device


@pytest.fixture(scope="session", autouse=True)
def require_device_emulator():
    if reachable():
        return
    reason = f"no device emulator on {HOST}:{PORT}"
    if os.environ.get("REQUIRE_DEVICE_EMULATOR", "").lower() in {"1", "true", "yes"}:
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture
def firewall():
    device = CiscoAsaFirewall(
        host=HOST, username=USERNAME, password=PASSWORD, port=PORT, device_id="FW_Edge"
    )
    yield device
    device.close()


@pytest.fixture
def session():
    config = ConfigSession(
        HOST, USERNAME, PASSWORD, device_type="cisco_asa", device_id="FW_Edge", port=PORT
    )
    yield config
    config.close()


@pytest.fixture
def clean(firewall, session):
    """Leave the device as it was found, whatever a test does to it."""
    yield
    session.send_config([f"no {COMMAND}", f"no {COMMAND.replace('extended ', 'line 39 extended ')}"])
    firewall.refresh("FW_Edge")


def action(**overrides) -> dict:
    base = {
        "device": "FW_Edge",
        "command": COMMAND,
        "rollback": f"no {COMMAND}",
        "position": 39,
        "verified": True,
        "rollback_verified": True,
    }
    base.update(overrides)
    return base


def test_a_real_session_reads_and_parses_live_policy(firewall):
    rules = firewall.acl_policy("FW_Edge")

    assert [rule.line for rule in rules] == [10, 40, 50]
    assert rules[1].action == "deny"
    assert rules[1].hits == 1284
    # Paging was disabled during session setup; otherwise this output would
    # arrive wrapped in "<--- More --->" and the parse would be truncated.
    assert rules[-1].raw


def test_the_flow_the_alert_describes_is_denied_on_the_device(firewall):
    denials = firewall.denied_flows(FLOW)
    assert denials
    assert denials[0]["action"] == "deny"


def test_the_read_only_guard_holds_over_a_real_channel(firewall):
    """The guarantee is worth only as much as it is worth on a live session."""
    for command in ("configure terminal", "no access-list DMZ_TO_TRUST line 40", "reload"):
        with pytest.raises(ReadOnlyViolation):
            firewall._send(command)

    # And the device is untouched afterwards.
    assert len(firewall.acl_policy("FW_Edge")) == 3


def test_a_change_sent_without_its_position_lands_shadowed(firewall, session, clean):
    """Why the position has to be materialised into the command.

    Appended after the deny at line 40, a correct-looking permit does nothing.
    This is the failure that post-change verification exists to catch.
    """
    session.send_config([COMMAND])
    firewall.refresh("FW_Edge")

    rules = firewall.acl_policy("FW_Edge")
    added = [rule for rule in rules if rule.action == "permit" and rule.port == 443]
    assert added, "the device accepted the command"
    assert added[0].line > 40, "and placed it after the deny, where it has no effect"


def test_the_rendered_command_carries_the_simulated_position(firewall, session, clean):
    lines = device_commands(COMMAND, 39, "cisco_asa")
    assert lines == [
        "access-list DMZ_TO_TRUST line 39 extended permit tcp host 10.10.1.10 "
        "host 10.20.1.50 eq 443"
    ]

    session.send_config(lines)
    firewall.refresh("FW_Edge")

    added = [r for r in firewall.acl_policy("FW_Edge") if r.action == "permit" and r.port == 443]
    assert added and added[0].line < 40, "the permit must be evaluated before the deny"


def test_apply_verify_and_a_device_that_confirms_the_change(firewall, clean):
    executor = DeviceExecutor(
        firewall,
        lambda _device: ConfigSession(
            HOST, USERNAME, PASSWORD, device_type="cisco_asa", device_id="FW_Edge", port=PORT
        ),
        devices={"FW_Edge"},
    )

    result = executor.apply([action()], FLOWS)

    assert result.state == "applied", result.lines
    assert any("LIVE PASS" in line for line in result.verification)
    # The confirmation was read back off the device, not predicted.
    assert firewall.denied_flows(FLOW) == []


def test_a_change_that_does_not_take_effect_is_rolled_back_on_the_device(firewall, clean):
    """The whole safety story, end to end, against something that really changes.

    Dropping the position reproduces the shadowed-append failure, so the change
    is applied for real, fails its read-back, and has to be removed for real.
    """
    executor = DeviceExecutor(
        firewall,
        lambda _device: ConfigSession(
            HOST, USERNAME, PASSWORD, device_type="cisco_asa", device_id="FW_Edge", port=PORT
        ),
        devices={"FW_Edge"},
    )

    result = executor.apply([action(position=None)], FLOWS)

    assert result.state == "rolled_back", result.lines
    assert any("LIVE FAIL" in line for line in result.verification)
    assert any("ROLLBACK PASS" in line for line in result.verification)

    # The device is genuinely back to its three seeded rules.
    firewall.refresh("FW_Edge")
    assert len(firewall.acl_policy("FW_Edge")) == 3
    assert firewall.denied_flows(FLOW)
