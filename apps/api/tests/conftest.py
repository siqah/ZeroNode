"""Shared fixtures for unit and integration tests."""

from __future__ import annotations

import os
import socket
from urllib.parse import urlparse

import pytest

from app.config import cypher_dir
from app.firewall.asa import CiscoAsaFirewall, ReadOnlyViolation


class FakeAsa(CiscoAsaFirewall):
    """Exercises the adapter without a device by replacing only the transport."""

    def __init__(
        self,
        acl_output: str,
        group_output: str = "",
        object_output: str = "",
        nat_output: str = "",
    ) -> None:
        super().__init__(host="192.0.2.10", username="ro", password="x")
        self.acl_output = acl_output
        self.group_output = group_output
        self.object_output = object_output
        self.nat_output = nat_output
        self.sent: list[str] = []

    def _send(self, command: str) -> str:
        if not command.strip().lower().startswith("show "):
            raise ReadOnlyViolation(command)
        self.sent.append(command)
        if "object-group" in command:
            return self.group_output
        if "running-config object" in command:
            return self.object_output
        if command.strip().lower() == "show nat":
            return self.nat_output
        return self.acl_output


@pytest.fixture
def fake_asa():
    return FakeAsa


POSTGRES_DSN = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://zeronode:zeronode@localhost:5433/zeronode"
)
NEO4J_URI = os.environ.get("TEST_NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("TEST_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("TEST_NEO4J_PASSWORD", "zeronode")


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def postgres_reachable() -> bool:
    parsed = urlparse(POSTGRES_DSN)
    return _reachable(parsed.hostname or "localhost", parsed.port or 5432)


def neo4j_reachable() -> bool:
    parsed = urlparse(NEO4J_URI.replace("bolt://", "http://"))
    return _reachable(parsed.hostname or "localhost", parsed.port or 7687)


@pytest.fixture(scope="session")
def require_postgres():
    if not postgres_reachable():
        pytest.fail(f"integration test requires Postgres at {POSTGRES_DSN}")
    return POSTGRES_DSN


@pytest.fixture(scope="session")
def require_neo4j():
    if not neo4j_reachable():
        pytest.fail(f"integration test requires Neo4j at {NEO4J_URI}")
    return {
        "uri": NEO4J_URI,
        "user": NEO4J_USER,
        "password": NEO4J_PASSWORD,
    }


@pytest.fixture
async def postgres_pool(require_postgres):
    pytest.importorskip("psycopg")
    from psycopg_pool import AsyncConnectionPool

    pool = AsyncConnectionPool(
        require_postgres,
        min_size=1,
        max_size=4,
        open=False,
        kwargs={"autocommit": True, "prepare_threshold": 0},
    )
    await pool.open(wait=True, timeout=10)
    async with pool.connection() as conn:
        await conn.execute(
            """
            TRUNCATE investigation_jobs, worker_heartbeats, execution_results,
                     approvals, incidents, users CASCADE
            """
        )
    yield pool
    await pool.close()


@pytest.fixture
def neo4j_topology(require_neo4j):
    from app.store.neo4j_store import Neo4jTopology

    store = Neo4jTopology(
        require_neo4j["uri"],
        require_neo4j["user"],
        require_neo4j["password"],
    )
    with store._driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    store.ensure_seed(cypher_dir())
    yield store
    store.close()
