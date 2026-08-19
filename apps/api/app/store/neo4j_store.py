from __future__ import annotations

from pathlib import Path

from neo4j import GraphDatabase

from app.store import BoundaryResult, NeighborImpact


def _statements(cypher: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    for line in cypher.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        buf.append(line)
        if stripped.endswith(";"):
            stmt = "\n".join(buf).strip().rstrip(";").strip()
            if stmt:
                statements.append(stmt)
            buf = []
    tail = "\n".join(buf).strip().rstrip(";").strip()
    if tail:
        statements.append(tail)
    return statements


class Neo4jTopology:
    def __init__(self, uri: str, user: str, password: str) -> None:
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self._driver.close()

    def ensure_seed(self, cypher_dir: Path) -> None:
        schema = (cypher_dir / "schema.cypher").read_text()
        seed = (cypher_dir / "seed.cypher").read_text()
        with self._driver.session() as session:
            links = session.run(
                "MATCH ()-[r:CONNECTS_TO]->() RETURN count(r) AS c"
            ).single()
            link_count = int(links["c"]) if links else 0
            if link_count >= 8:
                return
            session.run("MATCH (n) DETACH DELETE n")
            for statement in _statements(schema) + _statements(seed):
                session.run(statement)

    def known_devices(self) -> list[str]:
        with self._driver.session() as session:
            result = session.run("MATCH (d:Device) RETURN d.name AS name ORDER BY name")
            return [record["name"] for record in result]

    def device_ip(self, device_name: str) -> str | None:
        query = """
        MATCH (d:Device {name: $name})
        OPTIONAL MATCH (d)-[:HAS_INTERFACE]->(i:Interface)
        RETURN coalesce(d.management_ip, i.ip_address) AS ip
        """
        with self._driver.session() as session:
            record = session.run(query, name=device_name).single()
            return record["ip"] if record and record["ip"] else None

    def path_trace(self, source_device: str, target_device: str) -> list[str] | None:
        query = """
        MATCH path = shortestPath(
          (source:Device {name: $src})-[:HAS_INTERFACE|CONNECTS_TO*1..15]-(dest:Device {name: $dst})
        )
        RETURN [n IN nodes(path) WHERE 'Device' IN labels(n) | n.name] AS path_nodes
        """
        with self._driver.session() as session:
            record = session.run(query, src=source_device, dst=target_device).single()
            if not record or not record["path_nodes"]:
                return None
            return list(record["path_nodes"])

    def blast_radius(self, device_name: str) -> list[NeighborImpact]:
        query = """
        MATCH (core:Device {name: $device_name})-[:HAS_INTERFACE]->(:Interface)
              -[:CONNECTS_TO]->(:Interface)<-[:HAS_INTERFACE]-(downstream:Device)
        OPTIONAL MATCH (downstream)-[:BELONGS_TO]->(zone:SecurityZone)
        RETURN DISTINCT downstream.name AS affected_device, zone.name AS security_zone
        """
        with self._driver.session() as session:
            rows = session.run(query, device_name=device_name)
            return [
                NeighborImpact(
                    device=row["affected_device"],
                    security_zone=row["security_zone"],
                )
                for row in rows
            ]

    def security_boundary(
        self, source_device: str, target_device: str
    ) -> BoundaryResult | None:
        query = """
        MATCH (source:Device {name: $src})-[:BELONGS_TO]->(sz1:SecurityZone),
              (dest:Device {name: $dst})-[:BELONGS_TO]->(sz2:SecurityZone)
        RETURN sz1.name AS source_zone, sz2.name AS dest_zone,
               CASE WHEN sz1.name <> sz2.name THEN true ELSE false END AS crosses_boundary
        """
        with self._driver.session() as session:
            record = session.run(query, src=source_device, dst=target_device).single()
            if not record:
                return None
            return BoundaryResult(
                source_zone=record["source_zone"],
                dest_zone=record["dest_zone"],
                crosses_boundary=bool(record["crosses_boundary"]),
            )
