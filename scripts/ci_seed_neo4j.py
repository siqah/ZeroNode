#!/usr/bin/env python3
"""Seed Neo4j for CI integration tests."""

from __future__ import annotations

import os
import sys

from neo4j import GraphDatabase

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "apps", "api"))

from app.config import cypher_dir  # noqa: E402
from app.store.neo4j_store import Neo4jTopology  # noqa: E402


def main() -> int:
    uri = os.environ.get("TEST_NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("TEST_NEO4J_USER", "neo4j")
    password = os.environ.get("TEST_NEO4J_PASSWORD", "zeronode")
    store = Neo4jTopology(uri, user, password)
    with store._driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    store.ensure_seed(cypher_dir())
    store.close()
    print(f"Neo4j seeded at {uri}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
