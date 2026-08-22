"""Schema setup against a real Postgres, through a pool configured as the API's.

The unit tests never create a table: they stub the store. That left a failure
nobody could see, because the pool sets `prepare_threshold=0` and a prepared
statement cannot carry more than one command, so DDL written as a script works
on a plain connection and fails on a pooled one. The API would not start.

Skipped unless Postgres is up:

    docker compose up -d postgres
    .venv/bin/pytest tests/test_integration_postgres.py
"""

import os
import socket
from urllib.parse import urlparse

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

import psycopg  # noqa: E402
from psycopg_pool import AsyncConnectionPool  # noqa: E402

from app.audit.store import ensure_approvals_table  # noqa: E402
from app.auth.store import ensure_users_table  # noqa: E402
from app.jobs.store import ensure_jobs_tables  # noqa: E402
from app.store.incidents import ensure_incidents_table  # noqa: E402

DSN = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://zeronode:zeronode@localhost:5433/zeronode"
)


def reachable() -> bool:
    parsed = urlparse(DSN)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not reachable(), reason=f"no postgres at {DSN}"),
]


@pytest.fixture
async def pool():
    # The same connection settings the API uses. `prepare_threshold=0` is the
    # part that matters: it is what turns a multi-command script into an error.
    pool = AsyncConnectionPool(
        DSN,
        min_size=1,
        max_size=2,
        open=False,
        kwargs={"autocommit": True, "prepare_threshold": 0},
    )
    await pool.open(wait=True, timeout=10)
    yield pool
    await pool.close()


async def test_the_schema_can_be_created_on_a_pooled_connection(pool):
    async with pool.connection() as conn:
        await ensure_users_table(conn)
        await ensure_approvals_table(conn)
        await ensure_incidents_table(conn)
        await ensure_jobs_tables(conn)


async def test_running_setup_twice_is_harmless(pool):
    """It runs on every start, so it has to be idempotent."""
    async with pool.connection() as conn:
        await ensure_users_table(conn)
        await ensure_users_table(conn)
        await ensure_approvals_table(conn)
        await ensure_approvals_table(conn)


async def test_the_columns_the_login_path_selects_all_exist(pool):
    from app.auth.store import USER_COLUMNS

    async with pool.connection() as conn:
        await ensure_users_table(conn)
        await conn.execute(f"SELECT {USER_COLUMNS} FROM users LIMIT 1")


async def test_the_approvals_trigger_really_refuses_an_update(pool):
    """The ledger's immutability claim is a database trigger, not a convention."""
    async with pool.connection() as conn:
        await ensure_approvals_table(conn)
        trigger = await conn.execute(
            """
            SELECT 1
            FROM pg_trigger
            WHERE tgname = 'approvals_no_mutate' AND NOT tgisinternal
            """
        )
        assert await trigger.fetchone()

        # Probe the same trigger function on a temporary table. Writing a fake
        # record to the real ledger contaminates the chain permanently: the
        # append-only trigger correctly prevents test cleanup, and every later
        # signed record then names the fake hash as its predecessor.
        await conn.execute(
            """
            CREATE TEMP TABLE approvals_trigger_probe
            (LIKE approvals INCLUDING ALL)
            """
        )
        await conn.execute(
            """
            CREATE TRIGGER approvals_probe_no_mutate
            BEFORE UPDATE OR DELETE ON approvals_trigger_probe
            FOR EACH ROW EXECUTE FUNCTION approvals_append_only()
            """
        )
        await conn.execute(
            """
            INSERT INTO approvals_trigger_probe
                (thread_id, decision, feedback, actor, actor_role, evidence,
                 created_at, prev_hash, hash, signature, key_id)
            VALUES ('t-trigger', 'approve', '', 'test', 'approver', '{}'::jsonb,
                    'now', 'prev', 'hash-trigger-test', 'sig', 'key')
            """
        )

        with pytest.raises(psycopg.errors.RaiseException):
            await conn.execute(
                """
                UPDATE approvals_trigger_probe
                SET decision = 'reject'
                WHERE hash = 'hash-trigger-test'
                """
            )
        with pytest.raises(psycopg.errors.RaiseException):
            await conn.execute(
                """
                DELETE FROM approvals_trigger_probe
                WHERE hash = 'hash-trigger-test'
                """
            )
