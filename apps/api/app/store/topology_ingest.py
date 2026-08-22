"""NetBox → Neo4j topology ingest with freshness metadata."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from neo4j import GraphDatabase

from app.store.netbox import NetboxClient, build_topology, to_cypher

logger = logging.getLogger(__name__)

META_ID = "current"


@dataclass(frozen=True)
class IngestResult:
    source: str
    ingested_at: str
    site: str
    device_count: int
    link_count: int
    warning_count: int
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "ingested_at": self.ingested_at,
            "site": self.site,
            "device_count": self.device_count,
            "link_count": self.link_count,
            "warning_count": self.warning_count,
        }


def write_meta(session, result: IngestResult) -> None:
    session.run(
        """
        MERGE (m:TopologyMeta {id: $id})
        SET m.source = $source,
            m.ingested_at = $ingested_at,
            m.site = $site,
            m.device_count = $device_count,
            m.link_count = $link_count,
            m.warning_count = $warning_count
        """,
        id=META_ID,
        source=result.source,
        ingested_at=result.ingested_at,
        site=result.site,
        device_count=result.device_count,
        link_count=result.link_count,
        warning_count=result.warning_count,
    )


def run_netbox_ingest(
    *,
    url: str,
    token: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    site: str = "",
    replace: bool = True,
    verify_tls: bool = True,
) -> IngestResult:
    """Pull NetBox inventory and write the graph plus a TopologyMeta node."""
    client = NetboxClient(url, token, verify=verify_tls)
    filters = {"site": site} if site else {}

    devices = client.devices(**filters)
    interfaces = client.interfaces(**filters)
    addresses = client.addresses()
    topology = build_topology(devices, interfaces, addresses)

    ingested_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    result = IngestResult(
        source="netbox",
        ingested_at=ingested_at,
        site=site,
        device_count=len(topology.devices),
        link_count=len(topology.links),
        warning_count=len(topology.warnings),
        warnings=tuple(topology.warnings),
    )

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    try:
        with driver.session() as session:
            if replace:
                session.run("MATCH (n) DETACH DELETE n")
            for statement, params in to_cypher(topology):
                session.run(statement, params)
            write_meta(session, result)
    finally:
        driver.close()

    logger.info(
        "topology ingest from NetBox: %s (%d warnings)",
        result.as_dict(),
        result.warning_count,
    )
    for warning in result.warnings[:20]:
        logger.warning("topology ingest: %s", warning)
    if len(result.warnings) > 20:
        logger.warning("topology ingest: ... and %d more warnings", len(result.warnings) - 20)
    return result
