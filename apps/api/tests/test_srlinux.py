"""Nokia SR Linux operational ACL report parsing."""

from app.firewall.base import FlowQuery
from app.firewall.srlinux import NokiaSrlinuxFirewall, parse_show_acl

SHOW_OUTPUT = """
Filter : DMZ_TO_TRUST
SubIf-Specific: input-only
Entry-stats : yes
Entries : 3

Entry 10
Match : protocol=tcp, 10.10.1.0/24(*)->10.20.1.0/24(80-80)
Action : accept
Match Packets : 42

Entry 40
Match : protocol=tcp, 10.10.1.0/24(*)->10.20.1.50/32(443-443)
Action : drop
Match Packets : 1284

Entry 50
Match : protocol=<undefined>, (*)->(*)
Action : drop
Match Packets : 0
"""


def test_parses_srlinux_entries_actions_and_counters():
    result = parse_show_acl(SHOW_OUTPUT, "DMZ_TO_TRUST")

    assert result.unparsed == []
    assert [rule.line for rule in result.rules] == [10, 40, 50]
    assert [rule.action for rule in result.rules] == ["permit", "deny", "deny"]
    assert result.rules[1].hits == 1284
    assert result.rules[1].rule_id == "DMZ_TO_TRUST-40"


def test_parses_prefixes_and_an_exact_destination_port():
    permit, deny, _ = parse_show_acl(SHOW_OUTPUT, "DMZ_TO_TRUST").rules

    assert permit.src == "10.10.1.0/24"
    assert permit.port == 80
    assert deny.dst == "10.20.1.50/32"
    assert deny.port == 443
    assert deny.matches("10.10.1.10", "10.20.1.50", 443, "tcp")


def test_a_port_range_is_left_unconstrained_not_narrowed_to_one_port():
    output = """
Entry 10
Match : protocol=tcp,10.0.0.0/8(any)->10.20.0.0/16(1000-2000)
Action : accept
"""
    rule = parse_show_acl(output, "RANGE").rules[0]
    assert rule.port is None


def test_an_incomplete_entry_stays_in_order_as_unparsed():
    output = """
Entry 10
Match : protocol=tcp,10.0.0.0/8(any)->10.20.0.0/16(443-443)
Entry 20
Action : drop
"""
    result = parse_show_acl(output, "BROKEN")
    assert [rule.line for rule in result.rules] == [10, 20]
    assert len(result.unparsed) == 2


class FakeSrl(NokiaSrlinuxFirewall):
    def __init__(self, output: str) -> None:
        super().__init__(host="192.0.2.30", username="admin", password="x")
        self.output = output
        self.sent: list[str] = []

    def _send(self, command: str) -> str:
        self.sent.append(command)
        return self.output


def test_backend_reports_the_live_deny():
    firewall = FakeSrl(SHOW_OUTPUT)
    denials = firewall.denied_flows(
        FlowQuery(
            source_device="Web_App",
            source_ip="10.10.1.10",
            target_device="DB_Primary",
            target_ip="10.20.1.50",
            port=443,
        )
    )

    assert denials[0]["rule_id"] == "DMZ_TO_TRUST-40"
    assert firewall.sent == [
        "show acl acl-filter DMZ_TO_TRUST type ipv4"
    ]


def test_refresh_forces_a_second_live_read():
    firewall = FakeSrl(SHOW_OUTPUT)
    firewall.acl_policy("FW_Edge")
    firewall.acl_policy("FW_Edge")
    assert len(firewall.sent) == 1

    firewall.refresh("FW_Edge")
    firewall.acl_policy("FW_Edge")
    assert len(firewall.sent) == 2
