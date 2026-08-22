#!/usr/bin/env python
"""Replace the seeded graph with an ingest from NetBox.

    python scripts/ingest_netbox.py --url http://localhost:8001 --token $NETBOX_TOKEN

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
from app.store.topology_ingest import run_netbox_ingest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest NetBox topology into Neo4j")
    parser.add_argument("--url", default=settings.netbox_url or "http://localhost:8001")
    parser.add_argument("--token", default=settings.netbox_token or "")
    parser.add_argument("--site", default=settings.topology_site, help="Limit to one NetBox site")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument(
        "--replace",
        action="store_true",
        default=settings.topology_replace_on_ingest,
        help="Delete the existing graph first, rather than merging on top of it",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report, write nothing")
    args = parser.parse_args()
    if not args.token:
        parser.error("set NETBOX_TOKEN or pass --token")

    if args.dry_run:
        from app.store.netbox import NetboxClient, build_topology, to_cypher

        client = NetboxClient(args.url, args.token, verify=not args.insecure)
        filters = {"site": args.site} if args.site else {}
        topology = build_topology(
            client.devices(**filters),
            client.interfaces(**filters),
            client.addresses(),
        )
        print(topology.summary())
        for warning in topology.warnings:
            print(f"  ! {warning}")
        print(f"\nDry run: {len(to_cypher(topology))} statements not executed.")
        return 0

    print(f"Reading {args.url} ...")
    result = run_netbox_ingest(
        url=args.url,
        token=args.token,
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password,
        site=args.site,
        replace=args.replace,
        verify_tls=not args.insecure,
    )
    print(result.as_dict())
    for warning in result.warnings:
        print(f"  ! {warning}")
    print(f"\nWrote {result.device_count} devices into {settings.neo4j_uri}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
