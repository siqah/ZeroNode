"""Integration tests against a real Neo4j instance."""

from __future__ import annotations

import pytest

from app.config import cypher_dir

pytestmark = pytest.mark.integration


def test_known_devices_matches_lab(neo4j_topology):
    assert neo4j_topology.known_devices() == [
        "DB_Primary",
        "FW_Edge",
        "SW_DMZ",
        "SW_TRUST",
        "Web_App",
    ]


def test_path_trace_web_to_db(neo4j_topology):
    path = neo4j_topology.path_trace("Web_App", "DB_Primary")
    assert path == ["Web_App", "SW_DMZ", "FW_Edge", "SW_TRUST", "DB_Primary"]


def test_security_boundary_crosses_zones(neo4j_topology):
    result = neo4j_topology.security_boundary("Web_App", "DB_Primary")
    assert result.crosses_boundary is True
    assert result.source_zone == "DMZ"
    assert result.dest_zone == "TRUST"


def test_blast_radius_fw_edge(neo4j_topology):
    impact = neo4j_topology.blast_radius("FW_Edge")
    devices = [item.device for item in impact]
    # blast_radius reports immediate L2 neighbors only (one hop), not transitive reach.
    assert set(devices) == {"SW_TRUST", "SW_DMZ"}


def test_device_ip_resolution(neo4j_topology):
    assert neo4j_topology.device_ip("Web_App") == "10.10.1.10"


def test_ensure_seed_idempotent(neo4j_topology):
    first = neo4j_topology.known_devices()
    neo4j_topology.ensure_seed(cypher_dir())
    assert neo4j_topology.known_devices() == first


def test_known_devices_scoped_to_lab_site(neo4j_topology):
    assert neo4j_topology.known_devices(site="lab") == [
        "DB_Primary",
        "FW_Edge",
        "SW_DMZ",
        "SW_TRUST",
        "Web_App",
    ]
    assert neo4j_topology.known_devices(site="DC2") == []


def test_path_trace_requires_matching_site(neo4j_topology):
    assert neo4j_topology.path_trace("Web_App", "DB_Primary", site="lab") == [
        "Web_App",
        "SW_DMZ",
        "FW_Edge",
        "SW_TRUST",
        "DB_Primary",
    ]
    assert neo4j_topology.path_trace("Web_App", "DB_Primary", site="DC2") is None
