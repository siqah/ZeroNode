"""Ingest from NetBox payloads, including the ones that do not cooperate."""

from app.store.netbox import build_topology, to_cypher, zone_of

DEVICES = [
    {
        "id": 1,
        "name": "FW_Edge",
        "role": {"slug": "firewall"},
        "device_type": {"manufacturer": {"name": "Cisco"}},
        "platform": {"slug": "asa"},
        "site": {"name": "DC1"},
        "primary_ip4": {"address": "10.0.0.1/24"},
        "custom_fields": {"security_zone": "dmz"},
        "tags": [],
    },
    {
        "id": 2,
        "name": "SW_TRUST",
        "role": {"slug": "switch"},
        "device_type": {"manufacturer": {"name": "Cisco"}},
        "platform": {"slug": "ios"},
        "site": {"name": "DC1"},
        "primary_ip4": {"address": "10.20.0.2/24"},
        "custom_fields": {},
        "tags": [{"name": "zone:TRUST"}],
    },
]

INTERFACES = [
    {
        "id": 10,
        "name": "Gi0/1",
        "device": {"name": "FW_Edge"},
        "enabled": True,
        "mac_address": "02:00:00:00:00:02",
        "cable": 5,
        "connected_endpoints": [{"name": "Gi0/1", "device": {"name": "SW_TRUST"}}],
    },
    {
        "id": 11,
        "name": "Gi0/1",
        "device": {"name": "SW_TRUST"},
        "enabled": True,
        "cable": 5,
        "connected_endpoints": [{"name": "Gi0/1", "device": {"name": "FW_Edge"}}],
    },
]

ADDRESSES = [
    {
        "address": "10.20.0.1/24",
        "assigned_object_id": 10,
        "assigned_object_type": "dcim.interface",
    }
]


def test_devices_interfaces_and_links_come_across():
    topology = build_topology(DEVICES, INTERFACES, ADDRESSES)

    assert [device.name for device in topology.devices] == ["FW_Edge", "SW_TRUST"]
    assert topology.devices[0].vendor == "Cisco"
    assert topology.devices[0].management_ip == "10.0.0.1"  # the prefix is stripped
    assert len(topology.interfaces) == 2
    assert topology.links == [("FW_Edge:Gi0/1", "SW_TRUST:Gi0/1")]


def test_a_link_is_recorded_once_not_once_per_end():
    topology = build_topology(DEVICES, INTERFACES)
    assert len(topology.links) == 1


def test_an_ip_assigned_to_an_interface_lands_on_it():
    topology = build_topology(DEVICES, INTERFACES, ADDRESSES)
    firewall_side = next(i for i in topology.interfaces if i.id == "FW_Edge:Gi0/1")
    assert firewall_side.ip_address == "10.20.0.1"


def test_a_zone_may_be_a_custom_field_or_a_tag():
    assert zone_of(DEVICES[0]) == "DMZ"  # custom field, upper-cased
    assert zone_of(DEVICES[1]) == "TRUST"  # tag


def test_a_device_with_no_zone_is_reported_rather_than_guessed():
    """A missing zone reads as 'no boundary crossed', which is the wrong answer."""
    devices = [{**DEVICES[0], "custom_fields": {}, "tags": []}]
    topology = build_topology(devices, [])

    assert topology.devices[0].zone == ""
    assert any("no security zone" in warning for warning in topology.warnings)


def test_an_untraceable_cable_is_reported_not_silently_dropped():
    """A cable through a patch panel is a real link NetBox cannot follow."""
    interfaces = [{**INTERFACES[0], "connected_endpoints": [], "cable": 7}]
    topology = build_topology(DEVICES, interfaces)

    assert topology.links == []
    assert any("could not trace" in warning for warning in topology.warnings)


def test_an_unnamed_device_is_skipped_because_the_graph_is_keyed_by_name():
    topology = build_topology([{"id": 9, "name": None}], [])
    assert topology.devices == []
    assert any("no name" in warning for warning in topology.warnings)


def test_an_interface_on_an_unknown_device_is_ignored():
    interfaces = [{**INTERFACES[0], "device": {"name": "NotInInventory"}}]
    topology = build_topology(DEVICES, interfaces)
    assert all(i.device != "NotInInventory" for i in topology.interfaces)


def test_the_cypher_matches_the_shape_the_traversal_expects():
    statements = to_cypher(build_topology(DEVICES, INTERFACES, ADDRESSES))
    text = " ".join(statement for statement, _ in statements)

    assert "MERGE (z:SecurityZone {name: $name})" in text
    assert "BELONGS_TO" in text
    assert "HAS_INTERFACE" in text
    assert "CONNECTS_TO" in text
    # Both directions, because the path query traverses undirected.
    assert text.count("MERGE (a)-[:CONNECTS_TO]->(b)") == 1
    assert text.count("MERGE (b)-[:CONNECTS_TO]->(a)") == 1


def test_nothing_is_interpolated_into_a_query_string():
    """Inventory data is not trusted enough to build Cypher out of."""
    hostile = [{**DEVICES[0], "name": "x') DETACH DELETE (n) //"}]
    statements = to_cypher(build_topology(hostile, []))
    assert all("DETACH DELETE" not in statement for statement, _ in statements)
    assert any(params.get("name", "").startswith("x')") for _, params in statements)


def test_the_summary_says_how_much_of_the_estate_has_a_zone():
    topology = build_topology(DEVICES, INTERFACES)
    assert "2/2 with a security zone" in topology.summary()
