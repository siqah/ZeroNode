from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


def _site_clause(alias: str, site: str) -> str:
    if not site:
        return ""
    return f" AND {alias}.site = $site"


class Neo4jTopology:
    def __init__(self, uri: str, user: str, password: str, *, site: str = "") -> None:
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._site = (site or "").strip()

    def close(self) -> None:
        self._driver.close()

    def _effective_site(self, site: str | None = None) -> str:
        return (site if site is not None else self._site) or ""

    def _params(self, site: str | None = None, **extra: Any) -> dict[str, Any]:
        params = dict(extra)
        effective = self._effective_site(site)
        if effective:
            params["site"] = effective
        return params

    def ensure_seed(self, cypher_dir: Path) -> None:
        schema = (cypher_dir / "schema.cypher").read_text()
        seed = (cypher_dir / "seed.cypher").read_text()
        with self._driver.session() as session:
            meta = session.run(
                "MATCH (m:TopologyMeta {id: 'current'}) RETURN m.source AS source"
            ).single()
            if meta and meta.get("source") == "netbox":
                return
            netbox_devices = session.run(
                "MATCH (d:Device {source: 'netbox'}) RETURN count(d) AS c"
            ).single()
            if netbox_devices and int(netbox_devices["c"] or 0) > 0:
                return
            links = session.run(
                "MATCH ()-[r:CONNECTS_TO]->() RETURN count(r) AS c"
            ).single()
            link_count = int(links["c"]) if links else 0
            if link_count >= 8:
                return
            session.run("MATCH (n) DETACH DELETE n")
            for statement in _statements(schema) + _statements(seed):
                session.run(statement)

    def freshness(self) -> dict[str, Any] | None:
        with self._driver.session() as session:
            record = session.run(
                """
                MATCH (m:TopologyMeta {id: 'current'})
                RETURN m.source AS source, m.ingested_at AS ingested_at, m.site AS site,
                       m.device_count AS device_count, m.link_count AS link_count,
                       m.warning_count AS warning_count
                """
            ).single()
            if not record:
                return None
            return {
                "source": record["source"],
                "ingested_at": record["ingested_at"],
                "site": record["site"] or "",
                "device_count": int(record["device_count"] or 0),
                "link_count": int(record["link_count"] or 0),
                "warning_count": int(record["warning_count"] or 0),
            }

    def age_seconds(self) -> float | None:
        meta = self.freshness()
        if not meta or not meta.get("ingested_at"):
            return None
        ingested = str(meta["ingested_at"]).replace("Z", "+00:00")
        try:
            stamp = datetime.fromisoformat(ingested)
        except ValueError:
            return None
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        return max(0.0, (datetime.now(UTC) - stamp).total_seconds())

    def known_devices(self, *, site: str | None = None) -> list[str]:
        effective = self._effective_site(site)
        site_filter = _site_clause("d", effective)
        query = f"MATCH (d:Device) WHERE true{site_filter} RETURN d.name AS name ORDER BY name"
        with self._driver.session() as session:
            result = session.run(query, **self._params(site=site))
            return [record["name"] for record in result]

    def device_ip(self, device_name: str, *, site: str | None = None) -> str | None:
        effective = self._effective_site(site)
        site_filter = _site_clause("d", effective)
        query = f"""
        MATCH (d:Device {{name: $name}})
        WHERE true{site_filter}
        OPTIONAL MATCH (d)-[:HAS_INTERFACE]->(i:Interface)
        RETURN coalesce(d.management_ip, i.ip_address) AS ip
        """
        with self._driver.session() as session:
            record = session.run(
                query, **self._params(site=site, name=device_name)
            ).single()
            return record["ip"] if record and record["ip"] else None

    def path_trace(
        self, source_device: str, target_device: str, *, site: str | None = None
    ) -> list[str] | None:
        effective = self._effective_site(site)
        if effective:
            query = """
            MATCH path = shortestPath(
              (source:Device {name: $src, site: $site})
              -[:HAS_INTERFACE|CONNECTS_TO*1..15]-
              (dest:Device {name: $dst, site: $site})
            )
            RETURN [n IN nodes(path) WHERE 'Device' IN labels(n) | n.name] AS path_nodes
            """
        else:
            query = """
            MATCH path = shortestPath(
              (source:Device {name: $src})
              -[:HAS_INTERFACE|CONNECTS_TO*1..15]-
              (dest:Device {name: $dst})
            )
            RETURN [n IN nodes(path) WHERE 'Device' IN labels(n) | n.name] AS path_nodes
            """
        with self._driver.session() as session:
            record = session.run(
                query, **self._params(site=site, src=source_device, dst=target_device)
            ).single()
            if not record or not record["path_nodes"]:
                return None
            return list(record["path_nodes"])

    def blast_radius(self, device_name: str, *, site: str | None = None) -> list[NeighborImpact]:
        effective = self._effective_site(site)
        if effective:
            query = """
            MATCH (core:Device {name: $device_name, site: $site})-[:HAS_INTERFACE]->(:Interface)
                  -[:CONNECTS_TO]->(:Interface)<-[:HAS_INTERFACE]-(downstream:Device {site: $site})
            OPTIONAL MATCH (downstream)-[:BELONGS_TO]->(zone:SecurityZone)
            RETURN DISTINCT downstream.name AS affected_device, zone.name AS security_zone
            """
        else:
            query = """
            MATCH (core:Device {name: $device_name})-[:HAS_INTERFACE]->(:Interface)
                  -[:CONNECTS_TO]->(:Interface)<-[:HAS_INTERFACE]-(downstream:Device)
            OPTIONAL MATCH (downstream)-[:BELONGS_TO]->(zone:SecurityZone)
            RETURN DISTINCT downstream.name AS affected_device, zone.name AS security_zone
            """
        with self._driver.session() as session:
            rows = session.run(query, **self._params(site=site, device_name=device_name))
            return [
                NeighborImpact(
                    device=row["affected_device"],
                    security_zone=row["security_zone"],
                )
                for row in rows
            ]

    def security_boundary(
        self, source_device: str, target_device: str, *, site: str | None = None
    ) -> BoundaryResult | None:
        effective = self._effective_site(site)
        if effective:
            query = """
            MATCH (source:Device {name: $src, site: $site})-[:BELONGS_TO]->(sz1:SecurityZone),
                  (dest:Device {name: $dst, site: $site})-[:BELONGS_TO]->(sz2:SecurityZone)
            RETURN sz1.name AS source_zone, sz2.name AS dest_zone,
                   CASE WHEN sz1.name <> sz2.name THEN true ELSE false END AS crosses_boundary
            """
        else:
            query = """
            MATCH (source:Device {name: $src})-[:BELONGS_TO]->(sz1:SecurityZone),
                  (dest:Device {name: $dst})-[:BELONGS_TO]->(sz2:SecurityZone)
            RETURN sz1.name AS source_zone, sz2.name AS dest_zone,
                   CASE WHEN sz1.name <> sz2.name THEN true ELSE false END AS crosses_boundary
            """
        with self._driver.session() as session:
            record = session.run(
                query, **self._params(site=site, src=source_device, dst=target_device)
            ).single()
            if not record:
                return None
            return BoundaryResult(
                source_zone=record["source_zone"],
                dest_zone=record["dest_zone"],
                crosses_boundary=bool(record["crosses_boundary"]),
            )
