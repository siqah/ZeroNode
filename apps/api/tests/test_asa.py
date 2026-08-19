import pytest

from app.firewall.asa import CiscoAsaFirewall, ReadOnlyViolation, parse_show_access_list
from app.firewall.base import FlowQuery
from app.verify import verify_change

# Captured from `show access-list DMZ_TO_TRUST` on an ASA, including the header
# noise and hit counters that surround the rules.
SHOW_OUTPUT = """
access-list cached ACL log flows: total 0, denied 0 (deny-flow-max 4096)
            alert-interval 300
access-list DMZ_TO_TRUST; 3 elements; name hash: 0x1a2b3c4d
access-list DMZ_TO_TRUST line 10 extended permit tcp 10.10.1.0 255.255.255.0 10.20.1.0 255.255.255.0 eq www (hitcnt=42) 0x8a3b1c2d
access-list DMZ_TO_TRUST line 40 extended deny tcp 10.10.1.0 255.255.255.0 host 10.20.1.50 eq https (hitcnt=1284) 0x4f2a9b71
access-list DMZ_TO_TRUST line 50 extended deny ip any any (hitcnt=0) 0x9c1d0e33
"""

OBJECT_GROUP_OUTPUT = """
access-list DMZ_TO_TRUST line 30 extended permit tcp object-group DM_INLINE_NET_1 host 10.20.1.50 eq 8443 (hitcnt=7) 0x1111aaaa
access-list DMZ_TO_TRUST line 40 extended deny tcp 10.10.1.0 255.255.255.0 host 10.20.1.50 eq https (hitcnt=1284) 0x4f2a9b71
"""


def test_parses_lines_actions_and_hit_counters():
    rules = parse_show_access_list(SHOW_OUTPUT).rules
    assert [rule.line for rule in rules] == [10, 40, 50]
    assert [rule.action for rule in rules] == ["permit", "deny", "deny"]
    assert rules[1].hits == 1284
    assert rules[1].rule_id == "DMZ_TO_TRUST-40"
    assert rules[1].acl == "DMZ_TO_TRUST"


def test_dotted_masks_and_port_aliases_resolve():
    rules = parse_show_access_list(SHOW_OUTPUT).rules
    permit, deny = rules[0], rules[1]
    assert permit.port == 80          # eq www
    assert deny.port == 443           # eq https
    assert deny.matches("10.10.1.10", "10.20.1.50", 443, "tcp")
    assert not deny.matches("10.99.1.10", "10.20.1.50", 443, "tcp")


def test_unmodellable_rules_are_kept_not_dropped():
    result = parse_show_access_list(OBJECT_GROUP_OUTPUT)
    assert len(result.unparsed) == 1
    unparsed = result.unparsed[0]
    assert unparsed.line == 30
    assert "object-group" in unparsed.raw
    assert not unparsed.matches("10.10.1.10", "10.20.1.50", 8443, "tcp")


def test_denied_flow_is_derived_from_live_policy(fake_asa):
    asa = fake_asa(SHOW_OUTPUT)
    rows = asa.denied_flows(
        FlowQuery(
            source_device="Web_App",
            source_ip="10.10.1.10",
            target_device="DB_Primary",
            target_ip="10.20.1.50",
            port=443,
        )
    )
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "DMZ_TO_TRUST-40"
    assert rows[0]["hits"] == 1284
    assert rows[0]["action"] == "deny"
    assert asa.sent == ["show access-list"]


def test_permitted_flow_reports_no_denies(fake_asa):
    asa = fake_asa(SHOW_OUTPUT)
    rows = asa.denied_flows(
        FlowQuery(
            source_device="Web_App",
            source_ip="10.10.1.10",
            target_device="DB_Primary",
            target_ip="10.20.1.50",
            port=80,
        )
    )
    assert rows == []


def test_adapter_refuses_to_send_a_write_command():
    asa = CiscoAsaFirewall(host="192.0.2.10", username="ro", password="x")
    with pytest.raises(ReadOnlyViolation):
        asa._send("configure terminal")


def test_verification_is_inconclusive_when_policy_is_partly_unmodelled(fake_asa):
    asa = fake_asa(OBJECT_GROUP_OUTPUT)
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 39,
            }
        ],
        [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}],
        asa,
    )
    assert report.ok is False
    assert any(line.startswith("INCONCLUSIVE") for line in report.lines)
    assert "must review the ACL order manually" in report.remediation


def test_live_policy_reproduces_the_lab_scenario_end_to_end(fake_asa):
    """The ASA path must reach the same verdicts as the fixture path."""
    asa = fake_asa(SHOW_OUTPUT)
    flow = [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}]

    shadowed = verify_change(
        [{"device": "FW_Edge", "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"}],
        flow,
        asa,
    )
    assert shadowed.ok is False
    assert "position=39" in shadowed.remediation

    corrected = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 39,
            }
        ],
        flow,
        asa,
    )
    assert corrected.ok is True
