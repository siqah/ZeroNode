"""Every proposal carries a reversal, and the reversal is simulated too."""

from app.firewall.mock import MockFirewall
from app.store.memory import InMemoryTopology
from app.tools import ToolContext
from app.tools.topology import ProposeChangeInput, handle_propose_change
from app.verify import derive_rollback, verify_rollback

FW = MockFirewall()
CTX = ToolContext(topology=InMemoryTopology(), firewall=FW)

FLOW = [
    {
        "src": "10.10.1.10",
        "dst": "10.20.1.50",
        "port": 443,
        "proto": "tcp",
        "rule_id": "ACL-DMZ-47",
    }
]

COMMAND = "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"


def action(command: str = COMMAND, position: int | None = 38) -> dict:
    return {
        "device": "FW_Edge",
        "action": "add_acl_exception",
        "command": command,
        "position": position,
    }


def state(attempts: int = 0) -> dict:
    return {"denied_flows": FLOW, "verify_attempts": attempts}


def test_the_reversal_of_adding_a_line_is_removing_it():
    assert derive_rollback(COMMAND) == f"no {COMMAND}"
    # Already a removal, so it is left alone.
    assert derive_rollback(f"no {COMMAND}") == f"no {COMMAND}"


def test_a_derived_removal_puts_the_flow_back_where_it_was():
    report = verify_rollback(action(), FLOW, FW)
    assert report.ok is True
    assert report.source == "derived"
    assert report.command == f"no {COMMAND}"
    assert any("ROLLBACK PASS" in line for line in report.lines)


def test_an_authored_removal_is_recognised_as_the_model_s_own():
    report = verify_rollback(action(), FLOW, FW, rollback=f"no {COMMAND}")
    assert report.ok is True
    assert report.source == "model"


def test_a_reversal_that_removes_a_different_rule_is_refused():
    report = verify_rollback(
        action(), FLOW, FW, rollback="no permit tcp host 10.10.1.99 host 10.20.1.50 eq 443"
    )
    assert report.ok is False
    assert "removes a different rule" in " ".join(report.lines)
    assert f"no {COMMAND}" in report.remediation


def test_a_reversal_that_is_not_a_command_is_refused():
    report = verify_rollback(action(), FLOW, FW, rollback="ring the network team")
    assert report.ok is False
    assert "does not parse" in " ".join(report.lines)


def test_a_compensating_deny_counts_when_it_actually_restores_the_verdict():
    """Not every rollback is a removal; some shops add an explicit deny instead."""
    report = verify_rollback(
        action(), FLOW, FW, rollback="deny tcp host 10.10.1.10 host 10.20.1.50 eq 443"
    )
    assert report.ok is True


def test_a_compensating_rule_that_leaves_the_flow_open_is_refused():
    report = verify_rollback(
        action(), FLOW, FW, rollback="permit tcp host 10.10.1.10 host 10.20.1.50 eq 80"
    )
    assert report.ok is False
    assert "ROLLBACK FAIL" in " ".join(report.lines)


def test_a_queued_proposal_carries_a_verified_rollback():
    args = ProposeChangeInput(
        device_id="FW_Edge",
        command=COMMAND,
        rationale="restore app to database",
        position=38,
    )
    result = handle_propose_change(args, state(), CTX)
    queued = result.state_update["pending_actions"][0]

    assert queued["rollback"] == f"no {COMMAND}"
    assert queued["rollback_source"] == "derived"
    assert queued["rollback_verified"] is True
    assert queued["verified"] is True
    assert "Rollback:" in result.content


def test_a_proposal_with_a_broken_rollback_goes_back_to_the_model():
    args = ProposeChangeInput(
        device_id="FW_Edge",
        command=COMMAND,
        rationale="restore app to database",
        position=38,
        rollback="no permit tcp host 10.10.1.99 host 10.20.1.50 eq 443",
    )
    result = handle_propose_change(args, state(), CTX)

    assert "pending_actions" not in result.state_update
    assert "rollback would not restore" in result.content
    assert result.state_update["verify_attempts"] == 1


def test_after_the_attempt_budget_the_proposal_is_shown_but_marked_unverified():
    """The human still sees it; what they must not see is a false clean bill."""
    args = ProposeChangeInput(
        device_id="FW_Edge",
        command=COMMAND,
        rationale="restore app to database",
        position=38,
        rollback="ring the network team",
    )
    result = handle_propose_change(args, state(attempts=3), CTX)
    queued = result.state_update["pending_actions"][0]

    assert queued["rollback_verified"] is False
    assert queued["verified"] is False
    assert "NOT VERIFIED" in result.content
