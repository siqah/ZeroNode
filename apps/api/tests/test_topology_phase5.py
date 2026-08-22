from datetime import UTC, datetime, timedelta

from app.firewall.normalize import normalise_vendor, parse_vendor_acl
from app.store.topology_ingest import IngestResult


def test_normalise_vendor_aliases():
    assert normalise_vendor("ASA") == "cisco_asa"
    assert normalise_vendor("ios") == "cisco_ios"
    assert normalise_vendor("nokia_srl") == "nokia_srl"


def test_parse_vendor_acl_cisco_line():
    rule = parse_vendor_acl(
        "cisco_asa",
        "access-list DMZ extended permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
    )
    assert rule.action == "permit"
    assert rule.src == "10.10.1.10"
    assert rule.dst == "10.20.1.50"
    assert rule.port == 443


def test_parse_vendor_acl_ios_wrapper():
    rule = parse_vendor_acl(
        "cisco_ios",
        "ip access-list extended INTERNAL permit tcp host 10.30.1.10 host 10.30.1.50 eq 8080",
    )
    assert rule.action == "permit"
    assert rule.port == 8080


def test_in_memory_topology_site_filter():
    from app.store.memory import InMemoryTopology

    devices = {
        "A": {"zone": "Z", "neighbors": ["B"], "ip": "10.0.0.1", "site": "DC1"},
        "B": {"zone": "Z", "neighbors": ["A", "C"], "ip": "10.0.0.2", "site": "DC1"},
        "C": {"zone": "Z", "neighbors": ["B"], "ip": "10.0.0.3", "site": "DC2"},
    }
    store = InMemoryTopology(devices)
    assert store.known_devices(site="DC1") == ["A", "B"]
    assert store.path_trace("A", "C", site="DC1") is None
    assert store.path_trace("A", "B", site="DC1") == ["A", "B"]


def test_scoped_topology_uses_incident_site():
    from app.store.memory import InMemoryTopology
    from app.store.site_scoped import scoped_topology

    devices = {
        "A": {"zone": "Z", "neighbors": ["B"], "ip": "10.0.0.1", "site": "DC1"},
        "B": {"zone": "Z", "neighbors": ["A"], "ip": "10.0.0.2", "site": "DC1"},
        "C": {"zone": "Z", "neighbors": [], "ip": "10.0.0.3", "site": "DC2"},
    }
    base = InMemoryTopology(devices)
    scoped = scoped_topology(base, "DC1")
    assert scoped.known_devices() == ["A", "B"]
    assert "C" not in scoped.known_devices()


def test_ingest_result_as_dict():
    result = IngestResult(
        source="netbox",
        ingested_at="2026-08-22T08:00:00Z",
        site="DC1",
        device_count=3,
        link_count=2,
        warning_count=1,
        warnings=("missing zone",),
    )
    payload = result.as_dict()
    assert payload["device_count"] == 3
    assert payload["source"] == "netbox"


def test_neo4j_age_seconds_parses_meta():
    from app.store.neo4j_store import Neo4jTopology

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def run(self, *_args, **_kwargs):
            return self

        def single(self):
            return {
                "source": "netbox",
                "ingested_at": (datetime.now(UTC) - timedelta(hours=2)).replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "site": "DC1",
                "device_count": 1,
                "link_count": 1,
                "warning_count": 0,
            }

    class FakeDriver:
        def session(self):
            return FakeSession()

    store = Neo4jTopology.__new__(Neo4jTopology)
    store._driver = FakeDriver()
    store._site = ""
    age = store.age_seconds()
    assert age is not None
    assert 7000 < age < 8000
