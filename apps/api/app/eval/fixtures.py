"""Named topology and firewall fixtures for the eval corpus."""

from __future__ import annotations

from app.firewall.mock import MockFirewall
from app.store.memory import InMemoryTopology

SAME_ZONE_DEVICES = {
    "App_Server": {
        "zone": "TRUST",
        "neighbors": ["SW_TRUST"],
        "ip": "10.30.1.10",
        "site": "DC1",
    },
    "SW_TRUST": {
        "zone": "TRUST",
        "neighbors": ["App_Server", "Internal_FW"],
        "ip": "10.30.0.2",
        "site": "DC1",
    },
    "Internal_FW": {
        "zone": "TRUST",
        "neighbors": ["SW_TRUST", "DB_Replica"],
        "ip": "10.30.0.1",
        "site": "DC1",
    },
    "DB_Replica": {
        "zone": "TRUST",
        "neighbors": ["Internal_FW"],
        "ip": "10.30.1.50",
        "site": "DC1",
    },
}

ASYMMETRIC_DEVICES = {
    "App_Server": {
        "zone": "APP",
        "neighbors": ["R1_A"],
        "ip": "10.40.1.10",
        "site": "DC1",
    },
    "R1_A": {
        "zone": "CORE",
        "neighbors": ["App_Server", "R2_B"],
        "ip": "10.40.0.1",
        "site": "DC1",
    },
    "R2_B": {
        "zone": "CORE",
        "neighbors": ["R1_A", "DB_Replica"],
        "ip": "10.40.0.2",
        "site": "DC1",
    },
    "DB_Replica": {
        "zone": "DATA",
        "neighbors": ["R2_B"],
        "ip": "10.40.1.50",
        "site": "DC1",
    },
}

MTU_DEVICES = {
    "App_Server": {
        "zone": "APP",
        "neighbors": ["Edge_Router"],
        "ip": "10.50.1.10",
        "site": "DC1",
    },
    "Edge_Router": {
        "zone": "CORE",
        "neighbors": ["App_Server", "Core_Switch"],
        "ip": "10.50.0.1",
        "site": "DC1",
    },
    "Core_Switch": {
        "zone": "CORE",
        "neighbors": ["Edge_Router", "DB_Replica"],
        "ip": "10.50.0.2",
        "site": "DC1",
    },
    "DB_Replica": {
        "zone": "DATA",
        "neighbors": ["Core_Switch"],
        "ip": "10.50.1.50",
        "site": "DC1",
    },
}

SAME_ZONE_DENIED = [
    {
        "src": "10.30.1.10",
        "src_device": "App_Server",
        "dst": "10.30.1.50",
        "dst_device": "DB_Replica",
        "port": 8080,
        "proto": "tcp",
        "action": "deny",
        "rule_id": "ACL-INT-20",
        "hits": 512,
        "last_seen": "2026-08-22T08:00:00Z",
    }
]

SAME_ZONE_ACL = [
    {
        "device": "Internal_FW",
        "rule_id": "ACL-INT-20",
        "acl": "INTERNAL",
        "line": 20,
        "action": "deny",
        "proto": "tcp",
        "src": "10.30.1.0/24",
        "dst": "10.30.1.50",
        "port": 8080,
        "hits": 512,
    }
]

TOPOLOGY_FIXTURES: dict[str, dict[str, dict]] = {
    "lab": {},
    "same_zone": SAME_ZONE_DEVICES,
    "asymmetric": ASYMMETRIC_DEVICES,
    "mtu": MTU_DEVICES,
}


def load_topology(name: str) -> InMemoryTopology:
    devices = TOPOLOGY_FIXTURES.get(name)
    if devices is None:
        raise KeyError(f"unknown topology fixture {name!r}")
    if not devices:
        return InMemoryTopology()
    return InMemoryTopology(devices)


def load_firewall(name: str) -> MockFirewall:
    if name in ("lab", "asymmetric", "mtu"):
        return MockFirewall()
    if name == "same_zone":
        return MockFirewall(
            denied_flows=SAME_ZONE_DENIED,
            acl_hits=SAME_ZONE_ACL,
            platform="cisco_ios",
        )
    raise KeyError(f"unknown firewall fixture {name!r}")
