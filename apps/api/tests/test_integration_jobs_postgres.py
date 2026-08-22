"""Postgres-backed job durability integration tests."""

from __future__ import annotations

import asyncio

import pytest

from app.jobs.dispatcher import PostgresDispatcher, QueueFull
from app.jobs.store import STATUS_DEAD, STATUS_QUEUED, ensure_jobs_tables

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_enqueue_dedupes_start_jobs(postgres_pool):
    dispatcher = PostgresDispatcher(postgres_pool, capacity=10, max_attempts=3)
    first_id, first_created = await dispatcher.enqueue_start("INC-P1", payload={"initial": {}})
    second_id, second_created = await dispatcher.enqueue_start("INC-P1", payload={"initial": {}})
    assert first_id == second_id
    assert first_created is True
    assert second_created is False


@pytest.mark.asyncio
async def test_queue_capacity_enforced(postgres_pool):
    dispatcher = PostgresDispatcher(postgres_pool, capacity=1, max_attempts=3)
    await dispatcher.enqueue_start("INC-P2")
    with pytest.raises(QueueFull):
        await dispatcher.enqueue_start("INC-P3")


@pytest.mark.asyncio
async def test_expired_lease_reclaimed(postgres_pool):
    dispatcher = PostgresDispatcher(postgres_pool, capacity=10, max_attempts=3)
    await dispatcher.enqueue_start("INC-P4")
    job = await dispatcher.claim("worker-a", lease_seconds=1)
    assert job is not None
    await asyncio.sleep(1.05)
    reclaimed = await dispatcher.reclaim_expired()
    assert reclaimed >= 1
    again = await dispatcher.claim("worker-b", lease_seconds=30)
    assert again is not None
    assert again.thread_id == "INC-P4"


@pytest.mark.asyncio
async def test_dead_letter_after_max_attempts(postgres_pool):
    dispatcher = PostgresDispatcher(postgres_pool, capacity=10, max_attempts=2)
    await dispatcher.enqueue_start("INC-P5")
    first = await dispatcher.claim("worker-a", lease_seconds=30)
    assert first is not None
    status = await dispatcher.fail(first, error="boom", retry_delay_seconds=0)
    assert status == STATUS_QUEUED
    second = await dispatcher.claim("worker-a", lease_seconds=30)
    assert second is not None
    status = await dispatcher.fail(second, error="boom again", retry_delay_seconds=0)
    assert status == STATUS_DEAD
    assert await dispatcher.latest_error("INC-P5") == "boom again"


@pytest.mark.asyncio
async def test_worker_heartbeat_visible(postgres_pool):
    dispatcher = PostgresDispatcher(postgres_pool, capacity=10, max_attempts=3)
    await dispatcher.touch_worker("worker-test", concurrency=1, meta={"host": "ci"})
    health = await dispatcher.health(stale_after_seconds=120)
    assert health["live_workers"] >= 1


@pytest.mark.asyncio
async def test_execution_result_idempotent(postgres_pool):
    dispatcher = PostgresDispatcher(postgres_pool, capacity=10, max_attempts=3)
    await dispatcher.put_execution("op-1", "INC-P6", {"state": "applied"})
    cached = await dispatcher.get_execution("op-1")
    assert cached == {"state": "applied"}
    await dispatcher.put_execution("op-1", "INC-P6", {"state": "applied"})
    async with postgres_pool.connection() as conn:
        await ensure_jobs_tables(conn)
        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) FROM execution_results WHERE operation_key = %s", ("op-1",))
            row = await cur.fetchone()
    assert int(row[0]) == 1


@pytest.mark.asyncio
async def test_enqueue_resume_dedupes_on_approval_hash(postgres_pool):
    dispatcher = PostgresDispatcher(postgres_pool, capacity=10, max_attempts=3)
    first = await dispatcher.enqueue_resume(
        "INC-P7",
        approval_hash="approval-hash-1",
        payload={"decision": "approve"},
    )
    second = await dispatcher.enqueue_resume(
        "INC-P7",
        approval_hash="approval-hash-1",
        payload={"decision": "approve"},
    )
    assert first == second
