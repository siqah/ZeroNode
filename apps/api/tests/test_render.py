"""The command sent to a device must be the command that was simulated."""

from app.execute.render import device_commands

ASA = "access-list DMZ_TO_TRUST extended permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"


def test_a_position_is_materialised_into_the_asa_command():
    """Without this the device appends the rule and the deny still shadows it."""
    assert device_commands(ASA, 39, "cisco_asa") == [
        "access-list DMZ_TO_TRUST line 39 extended permit tcp host 10.10.1.10 "
        "host 10.20.1.50 eq 443"
    ]


def test_no_position_means_the_command_is_sent_as_written():
    assert device_commands(ASA, None, "cisco_asa") == [ASA]


def test_a_position_already_written_into_the_command_is_left_alone():
    explicit = "access-list DMZ_TO_TRUST line 12 extended permit ip any any"
    assert device_commands(explicit, 39, "cisco_asa") == [explicit]


def test_a_removal_keeps_its_negation_at_the_front():
    lines = device_commands(f"no {ASA}", 39, "cisco_asa")
    assert lines == [
        "no access-list DMZ_TO_TRUST line 39 extended permit tcp host 10.10.1.10 "
        "host 10.20.1.50 eq 443"
    ]


def test_ios_sequences_the_entry_inside_the_named_acl():
    """IOS puts the sequence number on the entry, not on the ACL line."""
    command = "ip access-list extended DMZ_TO_TRUST permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"
    assert device_commands(command, 39, "cisco_ios") == [
        "ip access-list extended DMZ_TO_TRUST",
        "39 permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
    ]


def test_ios_removal_negates_the_entry_not_the_access_list():
    """`no ip access-list extended X` would delete the entire ACL."""
    command = "no ip access-list extended DMZ_TO_TRUST permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"
    lines = device_commands(command, 39, "cisco_ios")
    assert lines[0] == "ip access-list extended DMZ_TO_TRUST"
    assert lines[1].startswith("no 39 permit")


def test_eos_uses_acl_mode_without_the_ios_extended_keyword():
    command = (
        "ip access-list extended DMZ_TO_TRUST permit tcp "
        "host 10.10.1.10 host 10.20.1.50 eq 443"
    )
    assert device_commands(command, 30, "arista_eos") == [
        "ip access-list DMZ_TO_TRUST",
        "30 permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
    ]


def test_eos_removes_a_sequenced_entry_by_its_number():
    command = (
        "no ip access-list extended DMZ_TO_TRUST permit tcp "
        "host 10.10.1.10 host 10.20.1.50 eq 443"
    )
    assert device_commands(command, 30, "arista_eos") == [
        "ip access-list DMZ_TO_TRUST",
        "no 30",
    ]


def test_srlinux_renders_a_modelled_ace_as_flat_candidate_commands():
    command = (
        "ip access-list extended DMZ_TO_TRUST permit tcp "
        "host 10.10.1.10 host 10.20.1.50 eq 443"
    )
    lines = device_commands(command, 30, "nokia_srl")

    assert lines == [
        "set / acl acl-filter DMZ_TO_TRUST type ipv4 entry 30 "
        "match ipv4 protocol tcp",
        "set / acl acl-filter DMZ_TO_TRUST type ipv4 entry 30 "
        "match ipv4 source-ip prefix 10.10.1.10/32",
        "set / acl acl-filter DMZ_TO_TRUST type ipv4 entry 30 "
        "match ipv4 destination-ip prefix 10.20.1.50/32",
        "set / acl acl-filter DMZ_TO_TRUST type ipv4 entry 30 "
        "match transport destination-port value 443",
        "set / acl acl-filter DMZ_TO_TRUST type ipv4 entry 30 action accept",
    ]


def test_srlinux_rollback_can_only_delete_the_numbered_acl_entry():
    command = (
        "no ip access-list extended DMZ_TO_TRUST permit tcp "
        "host 10.10.1.10 host 10.20.1.50 eq 443"
    )
    assert device_commands(command, 30, "nokia_srl") == [
        "delete / acl acl-filter DMZ_TO_TRUST type ipv4 entry 30"
    ]


def test_an_unrecognised_command_is_passed_through_untouched():
    assert device_commands("permit tcp any any", 39, "cisco_asa") == ["permit tcp any any"]


def test_an_empty_command_produces_nothing_to_send():
    assert device_commands("", 39, "cisco_asa") == []
