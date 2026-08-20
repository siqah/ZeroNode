"""Reading topology from NetBox instead of a seed file written to fit the queries.

The hand-written seed is honest about the workflow and dishonest about the data:
it contains exactly the devices, interfaces and cables the traversal needs, laid
out the way the traversal expects. A real inventory does not cooperate. Devices
have interfaces with no cable, cables terminate on front and rear ports through
patch panels, names collide across sites, and half the estate has no zone
recorded at all.

This reads NetBox over its REST API and produces the same graph shape the seed
produces, so the difference between the two is the data rather than the model.
Read-only: nothing here writes to NetBox.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

PAGE_SIZE = 200
# How a zone is recorded. Checked in this order, first hit wins.
ZONE_CUSTOM_FIELD = "security_zone"
ZONE_TAG_PREFIX = "zone:"


@dataclass
class Interface:
    device: str
    name: str
    ip_address: str = ""
    mac_address: str = ""
    enabled: bool = True

    @property
    def id(self) -> str:
        return f"{self.device}:{self.name}"


@dataclass
class Device:
    name: str
    role: str = ""
    vendor: str = ""
    platform: str = ""
    site: str = ""
    management_ip: str = ""
    zone: str = ""


@dataclass
class Topology:
    devices: list[Device] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        zoned = sum(1 for device in self.devices if device.zone)
        return (
            f"{len(self.devices)} devices, {len(self.interfaces)} interfaces, "
            f"{len(self.links)} links, {zoned}/{len(self.devices)} with a security zone"
        )


def _strip_prefix(address: str) -> str:
    """NetBox stores `10.10.1.10/24`; the graph and the ACLs want the address."""
    return (address or "").split("/")[0]


def zone_of(device: dict[str, Any]) -> str:
    custom = (device.get("custom_fields") or {}).get(ZONE_CUSTOM_FIELD)
    if custom:
        return str(custom).strip().upper()

    for tag in device.get("tags") or []:
        name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        if name.lower().startswith(ZONE_TAG_PREFIX):
            return name.split(":", 1)[1].strip().upper()

    return ""


class NetboxClient:
    """A paginating, read-only NetBox reader."""

    def __init__(self, url: str, token: str, *, verify: bool = True, timeout: float = 20.0) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.verify = verify
        self.timeout = timeout

    def _get(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        import httpx

        results: list[dict[str, Any]] = []
        query = {"limit": PAGE_SIZE, **(params or {})}
        next_url: str | None = f"{self.url}/api/{path.strip('/')}/"

        with httpx.Client(timeout=self.timeout, verify=self.verify) as client:
            while next_url:
                response = client.get(
                    next_url,
                    params=query if next_url.endswith("/") else None,
                    headers={
                        "Authorization": f"Token {self.token}",
                        "Accept": "application/json",
                    },
                )
                response.raise_for_status()
                body = response.json()
                results.extend(body.get("results", []))
                next_url = body.get("next")
                query = {}

        return results

    def devices(self, **filters: Any) -> list[dict[str, Any]]:
        return self._get("dcim/devices", filters)

    def interfaces(self, **filters: Any) -> list[dict[str, Any]]:
        return self._get("dcim/interfaces", filters)

    def addresses(self, **filters: Any) -> list[dict[str, Any]]:
        return self._get("ipam/ip-addresses", filters)


def build_topology(
    devices: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    addresses: list[dict[str, Any]] | None = None,
) -> Topology:
    """Turn NetBox payloads into the graph, saying what it had to skip."""
    topology = Topology()

    by_interface_id: dict[int, str] = {}
    for record in devices:
        name = record.get("name")
        if not name:
            # NetBox allows unnamed devices; the graph is keyed by name.
            topology.warnings.append(f"device {record.get('id')} has no name and was skipped")
            continue

        zone = zone_of(record)
        if not zone:
            topology.warnings.append(f"{name} has no security zone recorded")

        topology.devices.append(
            Device(
                name=name,
                role=((record.get("role") or record.get("device_role") or {}).get("slug") or ""),
                vendor=((record.get("device_type") or {}).get("manufacturer") or {}).get("name")
                or "",
                platform=((record.get("platform") or {}).get("slug") or ""),
                site=((record.get("site") or {}).get("name") or ""),
                management_ip=_strip_prefix(
                    (record.get("primary_ip4") or record.get("primary_ip") or {}).get("address", "")
                ),
                zone=zone,
            )
        )

    known = {device.name for device in topology.devices}

    address_by_interface: dict[int, str] = {}
    for record in addresses or []:
        assigned = record.get("assigned_object_id")
        if assigned and record.get("assigned_object_type") == "dcim.interface":
            address_by_interface[assigned] = _strip_prefix(record.get("address", ""))

    for record in interfaces:
        device_name = (record.get("device") or {}).get("name")
        if not device_name or device_name not in known:
            continue

        interface = Interface(
            device=device_name,
            name=record.get("name", ""),
            ip_address=address_by_interface.get(record.get("id"), ""),
            mac_address=record.get("mac_address") or "",
            enabled=bool(record.get("enabled", True)),
        )
        topology.interfaces.append(interface)
        by_interface_id[record.get("id")] = interface.id

    seen: set[tuple[str, str]] = set()
    for record in interfaces:
        source = by_interface_id.get(record.get("id"))
        if source is None:
            continue

        peers = record.get("connected_endpoints") or []
        if not peers and record.get("cable"):
            # A cable that lands on a patch panel has no traced endpoint. The
            # link is real, but NetBox cannot tell us where it ends.
            topology.warnings.append(
                f"{source} has a cable NetBox could not trace to an interface"
            )

        for peer in peers:
            if not isinstance(peer, dict):
                continue
            peer_device = (peer.get("device") or {}).get("name")
            peer_name = peer.get("name")
            if not peer_device or not peer_name:
                continue
            target = f"{peer_device}:{peer_name}"
            if target not in by_interface_id.values():
                continue
            edge = tuple(sorted((source, target)))
            if edge in seen:
                continue
            seen.add(edge)
            topology.links.append((source, target))

    return topology


def to_cypher(topology: Topology) -> list[tuple[str, dict[str, Any]]]:
    """Parameterised statements, in dependency order."""
    statements: list[tuple[str, dict[str, Any]]] = []

    for zone in sorted({device.zone for device in topology.devices if device.zone}):
        statements.append(("MERGE (z:SecurityZone {name: $name})", {"name": zone}))

    for device in topology.devices:
        statements.append(
            (
                """
                MERGE (d:Device {name: $name})
                SET d.type = $role, d.vendor = $vendor, d.os_version = $platform,
                    d.management_ip = $management_ip, d.site = $site, d.source = 'netbox'
                """,
                {
                    "name": device.name,
                    "role": device.role,
                    "vendor": device.vendor,
                    "platform": device.platform,
                    "management_ip": device.management_ip,
                    "site": device.site,
                },
            )
        )
        if device.zone:
            statements.append(
                (
                    """
                    MATCH (d:Device {name: $name}), (z:SecurityZone {name: $zone})
                    MERGE (d)-[:BELONGS_TO]->(z)
                    """,
                    {"name": device.name, "zone": device.zone},
                )
            )

    for interface in topology.interfaces:
        statements.append(
            (
                """
                MERGE (i:Interface {id: $id})
                SET i.name = $name, i.ip_address = $ip, i.mac_address = $mac,
                    i.status = $status
                """,
                {
                    "id": interface.id,
                    "name": interface.name,
                    "ip": interface.ip_address,
                    "mac": interface.mac_address,
                    "status": "up" if interface.enabled else "down",
                },
            )
        )
        statements.append(
            (
                """
                MATCH (d:Device {name: $device}), (i:Interface {id: $id})
                MERGE (d)-[:HAS_INTERFACE]->(i)
                """,
                {"device": interface.device, "id": interface.id},
            )
        )

    for source, target in topology.links:
        statements.append(
            (
                """
                MATCH (a:Interface {id: $a}), (b:Interface {id: $b})
                MERGE (a)-[:CONNECTS_TO]->(b)
                MERGE (b)-[:CONNECTS_TO]->(a)
                """,
                {"a": source, "b": target},
            )
        )

    return statements
