#!/usr/bin/env python
"""Replace the seeded graph with an ingest from NetBox.

    python scripts/ingest_netbox.py --url http://localhost:8000 --token $NETBOX_TOKEN

Reads NetBox, writes Neo4j, and says what it could not model. A device with no
security zone, or a cable NetBox cannot trace end to end, is reported rather
than guessed at: the agent's boundary check is only as good as the zones behind
it, and a silently missing zone reads as "no boundary crossed".
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api"))

from app.config import settings  # noqa: E402
from app.store.netbox import NetboxClient, build_topology, to_cypher  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest NetBox topology into Neo4j")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--token", required=True)
    parser.add_argument("--site", default="", help="Limit to one NetBox site")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Delete the existing graph first, rather than merging on top of it",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report, write nothing")
    args = parser.parse_args()

    client = NetboxClient(args.url, args.token, verify=not args.insecure)
    filters = {"site": args.site} if args.site else {}

    print(f"Reading {args.url} ...")
    devices = client.devices(**filters)
    interfaces = client.interfaces(**filters)
    addresses = client.addresses()

    topology = build_topology(devices, interfaces, addresses)
    print(topology.summary())

    for warning in topology.warnings:
        print(f"  ! {warning}")

    if not topology.links:
        print(
            "\nNo traced links. The path trace needs cables between interfaces, so the "
            "agent will report no physical path until NetBox has them."
        )

    if args.dry_run:
        print(f"\nDry run: {len(to_cypher(topology))} statements not executed.")
        return 0

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    with driver.session() as session:
        if args.replace:
            session.run("MATCH (n) DETACH DELETE n")
        for statement, params in to_cypher(topology):
            session.run(statement, params)
    driver.close()

    print(f"\nWrote {len(topology.devices)} devices into {settings.neo4j_uri}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
