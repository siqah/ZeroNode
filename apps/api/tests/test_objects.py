"""Named objects: `object network` / `object service` and their use in ACLs."""

from app.firewall.asa import parse_show_access_list
from app.firewall.objectgroup import (
    expand_group,
    expand_object,
    parse_show_object_groups,
    parse_show_objects,
)
from app.verify import verify_change

SHOW_OBJECTS = """
object network WEB_HOST
 host 10.10.1.10
object network DMZ_NET
 subnet 10.10.2.0 255.255.255.0
object network SMALL_RANGE
 range 10.10.3.8 10.10.3.11
object network CDN_ORIGIN
 fqdn origin.example.net
object service HTTPS_SVC
 service tcp destination eq https
object network DB_HOST
 host 10.20.1.50
"""

SHOW_OBJECT_GROUP_WITH_OBJECTS = """
object-group network APP_TIER
 network-object object WEB_HOST
 network-object object DMZ_NET
object-group service APP_PORTS
 service-object object HTTPS_SVC
 service-object tcp destination eq 8443
object-group network DANGLING
 network-object object MISSING_OBJECT
"""


def objects():
    return parse_show_objects(SHOW_OBJECTS)


def groups():
    return parse_show_object_groups(SHOW_OBJECT_GROUP_WITH_OBJECTS)


def test_host_subnet_and_range_objects_are_parsed():
    parsed = objects()
    assert parsed["web_host"].networks == ["10.10.1.10"]
    assert parsed["dmz_net"].networks == ["10.10.2.0/255.255.255.0"]
    # A four-address range collapses into a single prefix.
    assert parsed["small_range"].networks == ["10.10.3.8/30"]
    assert parsed["https_svc"].ports == [443]


def test_an_fqdn_object_is_marked_incomplete_rather_than_ignored():
    parsed = objects()
    assert parsed["cdn_origin"].complete is False
    assert expand_object("CDN_ORIGIN", parsed).complete is False


def test_a_group_of_objects_expands_through_both_layers():
    expansion = expand_group("APP_TIER", groups(), objects())
    assert expansion.complete is True
    assert expansion.networks == ["10.10.1.10", "10.10.2.0/255.255.255.0"]


def test_a_service_group_pulls_ports_from_a_named_object():
    expansion = expand_group("APP_PORTS", groups(), objects())
    assert expansion.complete is True
    assert sorted(expansion.ports) == [443, 8443]


def test_a_group_referencing_an_unknown_object_stays_incomplete():
    expansion = expand_group("DANGLING", groups(), objects())
    assert expansion.complete is False


def test_acl_written_against_named_objects_is_modelled():
    acl = (
        "access-list DMZ_TO_TRUST line 10 extended deny tcp object WEB_HOST "
        "object DB_HOST eq https (hitcnt=7) 0xabcd0001\n"
    )
    result = parse_show_access_list(acl, groups(), objects())
    assert result.unparsed == []
    assert len(result.rules) == 1
    rule = result.rules[0]
    assert (rule.action, rule.src, rule.dst, rule.port) == (
        "deny",
        "10.10.1.10",
        "10.20.1.50",
        443,
    )


def test_acl_using_a_service_object_as_the_protocol_carrier():
    acl = (
        "access-list DMZ_TO_TRUST line 20 extended permit object HTTPS_SVC "
        "object WEB_HOST object DB_HOST (hitcnt=1) 0xabcd0002\n"
    )
    result = parse_show_access_list(acl, groups(), objects())
    assert result.unparsed == []
    assert result.rules[0].port == 443
    assert result.rules[0].proto == "tcp"


def test_named_objects_are_read_and_close_an_otherwise_unmodellable_deny(fake_asa):
    acl = (
        "access-list DMZ_TO_TRUST line 10 extended deny tcp object WEB_HOST "
        "object DB_HOST eq https (hitcnt=7) 0xabcd0001\n"
        "access-list DMZ_TO_TRUST line 20 extended deny ip any any (hitcnt=3) 0xabcd0002\n"
    )
    asa = fake_asa(acl, "", SHOW_OBJECTS)
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 9,
            }
        ],
        [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}],
        asa,
    )
    assert "show running-config object" in asa.sent
    assert report.ok is True
    assert not any(line.startswith("INCONCLUSIVE") for line in report.lines)


def test_a_rule_on_an_unreadable_object_stays_inconclusive(fake_asa):
    """Placing the fix below a deny we cannot model must not read as a pass."""
    acl = (
        "access-list DMZ_TO_TRUST line 10 extended deny tcp object UNKNOWN_OBJ "
        "any eq https (hitcnt=7) 0xabcd0001\n"
    )
    asa = fake_asa(acl, "", SHOW_OBJECTS)
    report = verify_change(
        [
            {
                "device": "FW_Edge",
                "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
                "position": 20,
            }
        ],
        [{"src": "10.10.1.10", "dst": "10.20.1.50", "port": 443, "proto": "tcp"}],
        asa,
    )
    assert report.ok is False
    assert any(line.startswith("INCONCLUSIVE") for line in report.lines)
