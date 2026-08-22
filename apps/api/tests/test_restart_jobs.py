"""Restart-safe job reclaim and durable failure visibility."""

from __future__ import annotations

import asyncio

import pytest

from app.jobs.dispatcher import InMemoryDispatcher
from app.jobs.runner import InvestigationRunner
from app.jobs.store import KIND_START


class Snapshot:
    def __init__(self, values=None, nxt=()):
        self.values = values or {}
        self.next = nxt


class FakeGraph:
    def __init__(self):
        self.started = 0
        self.fail_once = False

    async def ainvoke(self, payload, config):
        self.started += 1
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("worker crashed mid-run")

    async def aget_state(self, config):
        return Snapshot({"messages": [("user", "x")]}, ())


class AppState:
    def __init__(self, graph):
        self.graph = graph
        self.tickets = _Null()
        self.notifier = _Null()
        self.schedule = None
        self.metrics = None
        self.pool = None
        self.keyset = None
        self.anchor_sink = None


class _Null:
    async def opened(self, *args, **kwargs):
        return None

    async def commented(self, *args, **kwargs):
        return None

    async def closed(self, *args, **kwargs):
        return None

    async def send(self, *args, **kwargs):
        return None


@pytest.mark.asyncio
async def test_a_crashed_worker_leaves_a_job_that_another_worker_can_finish():
    dispatcher = InMemoryDispatcher(max_attempts=3)
    graph = FakeGraph()
    graph.fail_once = True
    runner = InvestigationRunner(AppState(graph))

    await dispatcher.enqueue_start("INC-R1", payload={"initial": {"messages": []}})
    job = await dispatcher.claim("worker-1", lease_seconds=30)
    assert job is not None
    with pytest.raises(RuntimeError):
        await runner.run_job(job)
    await dispatcher.fail(job, error="worker crashed mid-run", retry_delay_seconds=0)

    # Simulate the original worker dying without completing the lease cleanup
    # beyond fail_job, then a second worker reclaiming the queued retry.
    again = await dispatcher.claim("worker-2", lease_seconds=30)
    assert again is not None
    assert again.kind == KIND_START
    await runner.run_job(again)
    await dispatcher.complete(again.id)
    assert graph.started == 2
    assert await dispatcher.latest_error("INC-R1") == ""


@pytest.mark.asyncio
async def test_worker_heartbeat_keeps_a_long_job_leased():
    dispatcher = InMemoryDispatcher()
    await dispatcher.enqueue_start("INC-R2", payload={"initial": {}})
    job = await dispatcher.claim("worker-1", lease_seconds=1)
    assert job is not None
    await asyncio.sleep(0.4)
    assert await dispatcher.heartbeat(job.id, "worker-1", lease_seconds=2)
    await asyncio.sleep(0.8)
    # Without the heartbeat the lease would have expired; with it, reclaim finds nothing.
    assert await dispatcher.reclaim_expired() == 0
