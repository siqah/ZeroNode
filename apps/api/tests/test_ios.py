"""Cisco IOS backend: wildcard masks, `(N matches)` counters, live NAT table."""

import pytest

from app.firewall.base import FlowQuery
from app.firewall.ios import (
    CiscoIosFirewall,
    parse_show_ip_access_lists,
    parse_show_ip_nat_translations,
    wildcard_to_prefix,
)
from app.firewall.ssh import ReadOnlyViolation
from app.verify import verify_change

SHOW_IP_ACCESS_LISTS = """
Extended IP access list DMZ_TO_TRUST
    10 permit tcp host 10.10.1.10 host 10.20.1.50 eq 80 (42 matches)
    20 deny tcp 10.10.1.0 0.0.0.255 host 10.20.1.50 eq 443 (1284 matches)
    30 permit ip any any (17 matches)
Standard IP access list MGMT
    10 permit 10.99.0.0, wildcard bits 0.0.0.255 (3 matches)
"""

FLOW = [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}]


class FakeIos(CiscoIosFirewall):
    def __init__(self, acl_output: str, nat_output: str = "") -> None:
        super().__init__(host="192.0.2.20", username="ro", password="x")
        self.acl_output = acl_output
        self.nat_output = nat_output
        self.sent: list[str] = []

    def _send(self, command: str) -> str:
        if not command.strip().lower().startswith("show "):
            raise ReadOnlyViolation(command)
        self.sent.append(command)
        return self.nat_output if "nat" in command else self.acl_output


def test_wildcard_bits_become_a_prefix():
    assert wildcard_to_prefix("10.10.1.0", "0.0.0.255") == "10.10.1.0/255.255.255.0"
    assert wildcard_to_prefix("10.10.1.10", "0.0.0.0") == "10.10.1.10/255.255.255.255"


def test_non_contiguous_wildcards_are_refused():
    """IOS allows them; a prefix cannot express them, so we must not guess."""
    assert wildcard_to_prefix("10.10.1.0", "0.0.255.0") is None


def test_entries_parse_with_sequence_numbers_and_hit_counters():
    result = parse_show_ip_access_lists(SHOW_IP_ACCESS_LISTS)
    assert result.unparsed == []
    extended = [rule for rule in result.rules if rule.acl == "DMZ_TO_TRUST"]
    assert [rule.line for rule in extended] == [10, 20, 30]
    deny = extended[1]
    assert (deny.action, deny.src, deny.dst, deny.port, deny.hits) == (
        "deny",
        "10.10.1.0/255.255.255.0",
        "10.20.1.50",
        443,
        1284,
    )


def test_a_standard_list_is_source_only():
    result = parse_show_ip_access_lists(SHOW_IP_ACCESS_LISTS)
    standard = [rule for rule in result.rules if rule.acl == "MGMT"][0]
    assert (standard.src, standard.dst, standard.proto) == ("10.99.0.0/255.255.255.0", "any", "ip")


def test_unsupported_port_operators_stay_unmodelled():
    result = parse_show_ip_access_lists(
        "Extended IP access list X\n    10 permit tcp any any gt 1024\n"
    )
    assert len(result.unparsed) == 1


def test_entries_without_sequence_numbers_are_ordered_as_written():
    result = parse_show_ip_access_lists(
        "Extended IP access list X\n"
        "    permit tcp host 10.0.0.1 any eq 22\n"
        "    deny ip any any\n"
    )
    assert [rule.line for rule in result.rules] == [10, 20]


def test_denied_flow_is_derived_from_the_parsed_policy():
    ios = FakeIos(SHOW_IP_ACCESS_LISTS)
    flows = ios.denied_flows(
        FlowQuery(
            source_device="Web_App",
            source_ip="10.10.1.10",
            target_device="DB_Primary",
            target_ip="10.20.1.50",
            port=443,
        )
    )
    assert len(flows) == 1
    assert flows[0]["rule_id"] == "DMZ_TO_TRUST-20"
    assert flows[0]["hits"] == 1284


def test_a_shadowed_proposal_is_caught_on_ios_too():
    ios = FakeIos(SHOW_IP_ACCESS_LISTS)
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 25,
            }
        ],
        FLOW,
        ios,
    )
    assert report.ok is False
    assert any("shadowed" in line for line in report.lines)


def test_the_same_rule_placed_above_the_deny_verifies():
    ios = FakeIos(SHOW_IP_ACCESS_LISTS)
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 15,
            }
        ],
        FLOW,
        ios,
    )
    assert report.ok is True


def test_an_active_translation_blocks_the_verdict():
    nat = (
        "Pro Inside global      Inside local       Outside local      Outside global\n"
        "tcp 203.0.113.10:443   10.10.1.10:443     10.20.1.50:443     10.20.1.50:443\n"
    )
    ios = FakeIos(SHOW_IP_ACCESS_LISTS, nat_output=nat)
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 15,
            }
        ],
        FLOW,
        ios,
    )
    assert report.ok is False
    assert any(line.startswith("INCONCLUSIVE") for line in report.lines)


def test_incomplete_translations_are_ignored():
    nat = (
        "Pro Inside global      Inside local       Outside local      Outside global\n"
        "--- 203.0.113.10       10.10.1.10         ---                ---\n"
    )
    assert parse_show_ip_nat_translations(nat) == [("203.0.113.10", "10.10.1.10")]


def test_the_ios_backend_refuses_to_send_anything_but_show():
    ios = CiscoIosFirewall(host="192.0.2.20", username="ro", password="x")
    with pytest.raises(ReadOnlyViolation):
        ios._send("configure terminal")
    with pytest.raises(ReadOnlyViolation):
        ios._send("access-list 100 permit ip any any")
