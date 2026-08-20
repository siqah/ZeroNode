"""Arista EOS parsing. Close to IOS, and different where it counts."""

from app.execute.render import device_commands
from app.firewall.base import FlowQuery
from app.firewall.eos import AristaEosFirewall, parse_show_ip_access_lists

# `show ip access-lists` on EOS: counters in brackets, no "Extended" in the
# header, and ports rendered as names.
SHOW_OUTPUT = """
IP Access List DMZ_TO_TRUST
        10 permit tcp 10.10.1.0/24 10.20.1.0/24 eq www [match 42, 0:02:11 ago]
        20 permit tcp host 10.10.1.20 host 10.20.1.50 eq 1521
        40 deny tcp 10.10.1.0/24 host 10.20.1.50 eq https [match 1284, 0:00:03 ago]
        50 deny ip any any
"""


def test_the_eos_header_and_bracketed_counters_are_understood():
    result = parse_show_ip_access_lists(SHOW_OUTPUT)

    assert result.unparsed == []
    assert [rule.line for rule in result.rules] == [10, 20, 40, 50]
    assert result.rules[0].acl == "DMZ_TO_TRUST"
    assert result.rules[2].hits == 1284
    assert result.rules[2].rule_id == "DMZ_TO_TRUST-40"


def test_a_rule_with_no_counter_is_not_mistaken_for_a_zero_length_body():
    result = parse_show_ip_access_lists(SHOW_OUTPUT)
    second = result.rules[1]
    assert second.hits == 0
    assert second.src == "10.10.1.20"
    assert second.port == 1521


def test_prefix_notation_and_port_names_resolve():
    """EOS writes prefixes; IOS writes wildcard masks. Reusing the IOS parser
    here would read 10.10.1.0/24 as an address with no mask."""
    result = parse_show_ip_access_lists(SHOW_OUTPUT)
    permit = result.rules[0]

    assert permit.src == "10.10.1.0/24"
    assert permit.port == 80
    assert permit.matches("10.10.1.10", "10.20.1.50", 80, "tcp")


def test_the_deny_that_the_scenario_depends_on_is_matched():
    deny = parse_show_ip_access_lists(SHOW_OUTPUT).rules[2]
    assert deny.action == "deny"
    assert deny.matches("10.10.1.10", "10.20.1.50", 443, "tcp")


def test_a_qualifier_we_cannot_model_leaves_the_rule_unparsed():
    """Better an admitted gap than a rule treated as wider than it is."""
    output = "IP Access List X\n    10 permit tcp any any eq 443 ttl eq 64\n"
    result = parse_show_ip_access_lists(output)

    assert len(result.unparsed) == 1
    assert "ttl" in result.unparsed[0].raw
    # It keeps its place in the list, because position is what shadowing turns on.
    assert result.rules[0].line == 10
    assert not result.rules[0].matches("10.1.1.1", "10.2.2.2", 443, "tcp")


def test_a_range_operator_is_not_pretended_to_be_a_single_port():
    output = "IP Access List X\n    10 permit tcp any any range 1000 2000\n"
    result = parse_show_ip_access_lists(output)
    assert result.unparsed
    assert result.rules[0].action == "unparsed"


def test_entries_outside_an_access_list_header_are_ignored():
    assert parse_show_ip_access_lists("    10 permit ip any any\n").rules == []


class FakeEos(AristaEosFirewall):
    def __init__(self, output: str) -> None:
        super().__init__(host="192.0.2.20", username="ro", password="x")
        self.output = output
        self.sent: list[str] = []

    def _send(self, command: str) -> str:
        self.sent.append(command)
        return self.output


def test_the_denied_flow_is_reported_with_the_rule_that_blocks_it():
    eos = FakeEos(SHOW_OUTPUT)
    denials = eos.denied_flows(
        FlowQuery(
            source_device="Web_App",
            source_ip="10.10.1.10",
            target_device="DB_Primary",
            target_ip="10.20.1.50",
            port=443,
        )
    )

    assert len(denials) == 1
    assert denials[0]["rule_id"] == "DMZ_TO_TRUST-40"


def test_hit_counters_carry_the_line_numbers_a_proposal_needs():
    hits = FakeEos(SHOW_OUTPUT).acl_hits("FW_Edge")
    assert [entry["line"] for entry in hits] == [10, 20, 40, 50]


def test_refresh_forces_a_second_read():
    eos = FakeEos(SHOW_OUTPUT)
    eos.acl_policy("FW_Edge")
    eos.acl_policy("FW_Edge")
    assert len(eos.sent) == 1

    eos.refresh("FW_Edge")
    eos.acl_policy("FW_Edge")
    assert len(eos.sent) == 2


def test_eos_changes_enter_eos_acl_mode_and_sequence_the_entry():
    command = "ip access-list extended DMZ_TO_TRUST permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"
    lines = device_commands(command, 39, "arista_eos")
    assert lines[0] == "ip access-list DMZ_TO_TRUST"
    assert lines[1].startswith("39 permit")
