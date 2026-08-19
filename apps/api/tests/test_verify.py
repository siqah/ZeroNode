from app.firewall.mock import MockFirewall
from app.firewall.policy import evaluate_flow, parse_acl_command
from app.verify import verify_change

FW = MockFirewall()

FLOW = [
    {
        "src": "10.10.1.10",
        "dst": "10.20.1.50",
        "port": 443,
        "proto": "tcp",
        "rule_id": "ACL-DMZ-47",
    }
]


def _action(command: str, position: int | None = None) -> list[dict]:
    return [
        {
            "device": "FW_Edge",
            "action": "add_acl_exception",
            "command": command,
            "position": position,
        }
    ]


def test_parse_host_form():
    rule = parse_acl_command("permit tcp host 10.10.1.10 host 10.20.1.50 eq 443")
    assert rule is not None
    assert rule.action == "permit"
    assert rule.proto == "tcp"
    assert rule.src == "10.10.1.10"
    assert rule.dst == "10.20.1.50"
    assert rule.port == 443


def test_parse_cidr_and_line_number():
    rule = parse_acl_command("line 39 permit tcp 10.10.1.0/24 10.20.1.0/24 eq 443")
    assert rule is not None
    assert rule.line == 39
    assert rule.src == "10.10.1.0/24"
    assert rule.dst == "10.20.1.0/24"


def test_permit_appended_below_the_deny_is_shadowed():
    report = verify_change(
        _action("permit tcp 10.10.1.0/24 10.20.1.0/24 eq 443"), FLOW, FW
    )
    assert report.ok is False
    assert any(line.startswith("FAIL") for line in report.lines)
    assert "ACL-DMZ-47" in " ".join(report.lines)
    assert "position=39" in report.remediation


def test_position_argument_places_the_rule_above_the_deny():
    report = verify_change(
        _action("permit tcp host 10.10.1.10 host 10.20.1.50 eq 443", position=39), FLOW, FW
    )
    assert report.ok is True
    assert any("inserting at line 39" in line for line in report.lines)


def test_subnet_wide_permit_is_rejected_as_over_permissive():
    report = verify_change(
        _action("permit tcp 10.10.1.0/24 10.20.1.0/24 eq 443", position=39), FLOW, FW
    )
    assert report.ok is False
    assert any(line.startswith("SCOPE") for line in report.lines)
    assert "64,516 host pairs but only 1" in " ".join(report.lines)
    assert "host 10.10.1.10 host 10.20.1.50" in report.remediation


def test_any_port_permit_is_flagged():
    report = verify_change(
        _action("permit tcp host 10.10.1.10 host 10.20.1.50", position=39), FLOW, FW
    )
    assert report.ok is False
    assert any("every port" in line for line in report.lines)


def test_permit_above_the_deny_verifies():
    report = verify_change(
        _action("line 39 permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"), FLOW, FW
    )
    assert report.ok is True
    assert any(line.startswith("PASS") for line in report.lines)


def test_unparseable_command_fails_verification():
    report = verify_change(_action("please open the firewall"), FLOW, FW)
    assert report.ok is False
    assert "could not parse" in " ".join(report.lines)


def test_first_match_wins_on_port():
    rules = [
        rule
        for rule in [
            parse_acl_command("line 10 permit tcp 10.10.1.0/24 10.20.1.0/24 eq 80"),
            parse_acl_command("line 40 deny tcp 10.10.1.0/24 host 10.20.1.50 eq 443"),
        ]
        if rule is not None
    ]
    action, hit = evaluate_flow(rules, "10.10.1.10", "10.20.1.50", 443)
    assert action == "deny"
    assert hit is not None and hit.line == 40

    action, _ = evaluate_flow(rules, "10.10.1.10", "10.20.1.50", 80)
    assert action == "permit"
