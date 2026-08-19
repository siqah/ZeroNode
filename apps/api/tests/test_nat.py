"""NAT detection: translated flows must not get a confident verdict."""

from app.firewall.nat import assess_flow, parse_show_nat
from app.firewall.objectgroup import parse_show_objects
from app.verify import verify_change

SHOW_NAT = """
Manual NAT Policies (Section 1)
1 (dmz) to (trust) source static WEB_HOST WEB_MAPPED destination static DB_HOST DB_HOST
    translate_hits = 12, untranslate_hits = 4
2 (dmz) to (trust) source static VPN_NET VPN_NET
    translate_hits = 0, untranslate_hits = 0

Auto NAT Policies (Section 2)
3 (dmz) to (outside) source dynamic DMZ_NET interface
    translate_hits = 900, untranslate_hits = 0
"""

SHOW_OBJECTS = """
object network WEB_HOST
 host 10.10.1.10
object network WEB_MAPPED
 host 203.0.113.10
object network DB_HOST
 host 10.20.1.50
object network VPN_NET
 subnet 10.99.0.0 255.255.255.0
object network DMZ_NET
 subnet 10.10.1.0 255.255.255.0
"""

ACL = (
    "access-list DMZ_TO_TRUST line 10 extended deny tcp host 10.10.1.10 "
    "host 10.20.1.50 eq https (hitcnt=9) 0xabcd0001\n"
)

FLOW = [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}]


def objects():
    return parse_show_objects(SHOW_OBJECTS)


def test_static_and_dynamic_rules_are_parsed_identity_is_flagged():
    rules = parse_show_nat(SHOW_NAT)
    assert [rule.kind for rule in rules] == ["static", "static", "static", "dynamic"]
    identity = [rule for rule in rules if rule.identity]
    assert len(identity) == 2  # the VPN exemption and the destination static DB_HOST DB_HOST


def test_a_translated_host_is_detected():
    assessment = assess_flow(parse_show_nat(SHOW_NAT), ["10.10.1.10"], objects())
    assert assessment.applies is True
    assert any("WEB_HOST WEB_MAPPED" in raw for raw in assessment.translated)


def test_identity_nat_does_not_count_as_translation():
    assessment = assess_flow(parse_show_nat(SHOW_NAT), ["10.99.0.5"], objects())
    assert assessment.applies is False


def test_an_untouched_address_is_not_flagged():
    assessment = assess_flow(parse_show_nat(SHOW_NAT), ["10.30.5.5"], objects())
    assert assessment.applies is False
    assert assessment.unresolved == []


def test_unresolvable_nat_operands_are_reported_but_do_not_claim_a_match():
    nat = "1 (dmz) to (trust) source static MYSTERY_OBJ OTHER_OBJ\n"
    assessment = assess_flow(parse_show_nat(nat), ["10.10.1.10"], {})
    assert assessment.applies is False
    assert assessment.unresolved


def test_config_style_nat_lines_are_parsed():
    rules = parse_show_nat("nat (dmz,trust) source static WEB_HOST WEB_MAPPED")
    assert len(rules) == 1
    assert rules[0].operands == ["WEB_HOST", "WEB_MAPPED"]


class NattedAsa:
    """An ASA whose ACL would pass the simulation, but which translates the flow."""

    def __init__(self, fake_asa, nat_output=SHOW_NAT):
        self.inner = fake_asa(ACL, "", SHOW_OBJECTS)
        self.nat_output = nat_output

    def describe(self):
        return self.inner.describe()

    def acl_policy(self, device_id):
        return self.inner.acl_policy(device_id)

    def denied_flows(self, query):
        return self.inner.denied_flows(query)

    def acl_hits(self, device_id, rule_id=None):
        return self.inner.acl_hits(device_id, rule_id)

    def nat_assessment(self, device_id, addresses):
        return assess_flow(parse_show_nat(self.nat_output), addresses, objects())


def test_a_translated_flow_blocks_the_verdict(fake_asa):
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 9,
            }
        ],
        FLOW,
        NattedAsa(fake_asa),
    )
    assert report.ok is False
    assert any(line.startswith("INCONCLUSIVE") and "translates" in line for line in report.lines)
    assert "untranslated" in report.remediation


def test_without_nat_the_same_change_verifies(fake_asa):
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 9,
            }
        ],
        FLOW,
        NattedAsa(fake_asa, nat_output=""),
    )
    assert report.ok is True


def test_a_backend_without_nat_support_still_verifies():
    from app.firewall.mock import MockFirewall

    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 39,
            }
        ],
        [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}],
        MockFirewall(),
    )
    assert report.ok is True
