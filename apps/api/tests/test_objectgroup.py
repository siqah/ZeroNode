from app.firewall.asa import parse_show_access_list
from app.firewall.objectgroup import expand_group, parse_show_object_groups
from app.firewall.policy import evaluate_flow
from app.verify import verify_change

SHOW_OBJECT_GROUP = """
object-group network DM_INLINE_NETWORK_1
 description app tier sources
 network-object host 10.10.1.10
 network-object 10.10.2.0 255.255.255.0
object-group network DB_HOSTS
 network-object host 10.20.1.50
 group-object DB_REPLICAS
object-group network DB_REPLICAS
 network-object host 10.20.1.51
object-group service WEB_PORTS tcp
 port-object eq https
 port-object range 8000 8002
object-group network PARTIAL_GRP
 network-object object SOME_NAMED_OBJECT
object-group service SVC_INLINE
 service-object tcp destination eq 8443
"""

# `show running-config access-list` leaves object-groups unexpanded.
UNEXPANDED_ACL = """
access-list DMZ_TO_TRUST line 30 extended permit tcp object-group DM_INLINE_NETWORK_1 object-group DB_HOSTS object-group WEB_PORTS (hitcnt=7) 0x1111aaaa
access-list DMZ_TO_TRUST line 40 extended deny ip any any (hitcnt=3) 0x2222bbbb
"""

# `show access-list` on the device expands each object-group into indented elements.
DEVICE_EXPANDED_ACL = """
access-list DMZ_TO_TRUST; 2 elements; name hash: 0x1a2b3c4d
access-list DMZ_TO_TRUST line 10 extended permit tcp object-group DM_INLINE_NETWORK_1 host 10.20.1.50 eq https (hitcnt=9) 0x11111111
  access-list DMZ_TO_TRUST line 10 extended permit tcp host 10.10.1.10 host 10.20.1.50 eq https (hitcnt=4) 0x22222222
  access-list DMZ_TO_TRUST line 10 extended permit tcp 10.10.2.0 255.255.255.0 host 10.20.1.50 eq https (hitcnt=5) 0x33333333
access-list DMZ_TO_TRUST line 20 extended deny ip any any (hitcnt=3) 0x44444444
"""


def groups():
    return parse_show_object_groups(SHOW_OBJECT_GROUP)


def test_network_service_and_nested_groups_parse():
    parsed = groups()
    assert parsed["dm_inline_network_1"].networks == [
        "10.10.1.10",
        "10.10.2.0/255.255.255.0",
    ]
    assert parsed["db_hosts"].members == ["db_replicas"]
    assert parsed["web_ports"].ports == [443, 8000, 8001, 8002]
    assert parsed["svc_inline"].ports == [8443]


def test_nested_groups_flatten():
    expansion = expand_group("DB_HOSTS", groups())
    assert expansion.networks == ["10.20.1.50", "10.20.1.51"]
    assert expansion.complete is True


def test_group_with_an_unreadable_member_is_incomplete():
    expansion = expand_group("PARTIAL_GRP", groups())
    assert expansion.complete is False


def test_cyclic_group_reference_terminates():
    cyclic = parse_show_object_groups(
        """
object-group network A
 group-object B
object-group network B
 group-object A
"""
    )
    expansion = expand_group("A", cyclic)
    assert expansion.complete is False


def test_unexpanded_rule_becomes_the_full_cross_product():
    rules = parse_show_access_list(UNEXPANDED_ACL, groups()).rules
    permits = [rule for rule in rules if rule.action == "permit"]
    # 2 sources x 2 destinations x 4 ports
    assert len(permits) == 16
    assert all(rule.line == 30 for rule in permits)
    assert all(rule.rule_id == "DMZ_TO_TRUST-30" for rule in permits)

    action, hit = evaluate_flow(rules, "10.10.1.10", "10.20.1.50", 443, "tcp")
    assert action == "permit"
    assert hit is not None and hit.rule_id == "DMZ_TO_TRUST-30"

    # A member of the nested group is covered too, but an unrelated host is not.
    assert evaluate_flow(rules, "10.10.1.10", "10.20.1.51", 8002, "tcp")[0] == "permit"
    assert evaluate_flow(rules, "10.10.9.9", "10.20.1.50", 443, "tcp")[0] == "deny"


def test_unexpanded_policy_verifies_without_inconclusive_verdicts():
    """Object-group resolution is what turns a real policy into a usable verdict."""
    rules = parse_show_access_list(UNEXPANDED_ACL, groups())
    assert rules.unparsed == []


def test_rule_using_an_incomplete_group_stays_unmodelled():
    acl = (
        "access-list DMZ_TO_TRUST line 30 extended permit tcp object-group PARTIAL_GRP "
        "host 10.20.1.50 eq https (hitcnt=0) 0xaaaa1111\n"
    )
    result = parse_show_access_list(acl, groups())
    assert len(result.unparsed) == 1
    assert "PARTIAL_GRP" in result.unparsed[0].raw


def test_device_expansion_is_used_and_the_summary_line_dropped():
    result = parse_show_access_list(DEVICE_EXPANDED_ACL)
    line_10 = [rule for rule in result.rules if rule.line == 10]
    assert result.unparsed == []
    assert len(line_10) == 2
    assert {rule.src for rule in line_10} == {
        "10.10.1.10",
        "10.10.2.0/255.255.255.0",
    }
    # Element counters, not the summary total.
    assert sorted(rule.hits for rule in line_10) == [4, 5]


def test_device_expansion_needs_no_object_group_lookup(fake_asa):
    asa = fake_asa(DEVICE_EXPANDED_ACL, SHOW_OBJECT_GROUP)
    rows = asa.acl_hits("FW_Edge")
    assert asa.sent == ["show access-list"]
    assert [row["line"] for row in rows] == [10, 20]
    assert rows[0]["src"] == "2 networks"


def test_unexpanded_policy_triggers_one_object_group_read(fake_asa):
    asa = fake_asa(UNEXPANDED_ACL, SHOW_OBJECT_GROUP)
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 31,
            }
        ],
        [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}],
        asa,
    )
    assert asa.sent == [
        "show access-list",
        "show object-group",
        "show running-config object",
        "show nat",
    ]
    assert not any(line.startswith("INCONCLUSIVE") for line in report.lines)
    # An object-group rule above the proposal already permits the flow, so the
    # change is redundant. Without expansion this would have read as a shadowed
    # proposal against an unmodellable policy.
    assert any("permitted, but by existing rule DMZ_TO_TRUST-30" in line for line in report.lines)
