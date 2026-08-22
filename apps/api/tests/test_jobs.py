"""Unit tests for the durable investigation queue."""

from __future__ import annotations

import asyncio

import pytest

from app.jobs.dispatcher import InMemoryDispatcher, QueueFull
from app.jobs.resilience import CircuitBreaker, CircuitOpen, call_with_retry
from app.jobs.store import STATUS_DEAD, STATUS_QUEUED


@pytest.mark.asyncio
async def test_enqueue_dedupes_identical_start_jobs():
    dispatcher = InMemoryDispatcher()
    first_id, first_created = await dispatcher.enqueue_start("INC-1", payload={"initial": {}})
    second_id, second_created = await dispatcher.enqueue_start("INC-1", payload={"initial": {}})
    assert first_id == second_id
    assert first_created is True
    assert second_created is False
    assert await dispatcher.depth() == 1


@pytest.mark.asyncio
async def test_queue_capacity_rejects_new_work():
    dispatcher = InMemoryDispatcher(capacity=1)
    await dispatcher.enqueue_start("INC-1")
    with pytest.raises(QueueFull):
        await dispatcher.enqueue_start("INC-2")


@pytest.mark.asyncio
async def test_expired_leases_are_reclaimed_and_retried():
    dispatcher = InMemoryDispatcher()
    await dispatcher.enqueue_start("INC-1")
    job = await dispatcher.claim("worker-a", lease_seconds=1)
    assert job is not None
    await asyncio.sleep(1.05)
    reclaimed = await dispatcher.reclaim_expired()
    assert reclaimed == 1
    again = await dispatcher.claim("worker-b", lease_seconds=30)
    assert again is not None
    assert again.thread_id == "INC-1"
    assert again.attempts == 2


@pytest.mark.asyncio
async def test_failed_jobs_dead_letter_after_max_attempts():
    dispatcher = InMemoryDispatcher(max_attempts=2)
    await dispatcher.enqueue_start("INC-1")
    first = await dispatcher.claim("worker-a", lease_seconds=30)
    assert first is not None
    status = await dispatcher.fail(first, error="boom", retry_delay_seconds=0)
    assert status == STATUS_QUEUED
    second = await dispatcher.claim("worker-a", lease_seconds=30)
    assert second is not None
    status = await dispatcher.fail(second, error="boom again", retry_delay_seconds=0)
    assert status == STATUS_DEAD
    assert await dispatcher.latest_error("INC-1") == "boom again"


@pytest.mark.asyncio
async def test_resume_jobs_dedupe_on_approval_hash():
    dispatcher = InMemoryDispatcher()
    first = await dispatcher.enqueue_resume(
        "INC-1",
        approval_hash="abc",
        payload={"decision": "approve"},
    )
    second = await dispatcher.enqueue_resume(
        "INC-1",
        approval_hash="abc",
        payload={"decision": "approve"},
    )
    assert first == second


def test_circuit_opens_after_threshold_failures():
    circuit = CircuitBreaker(failure_threshold=2, reset_seconds=60)

    def boom():
        raise TimeoutError("hung")

    with pytest.raises(TimeoutError):
        call_with_retry(
            boom,
            timeout_seconds=1,
            max_retries=0,
            backoff_seconds=0.01,
            circuit=circuit,
        )
    with pytest.raises(TimeoutError):
        call_with_retry(
            boom,
            timeout_seconds=1,
            max_retries=0,
            backoff_seconds=0.01,
            circuit=circuit,
        )
    assert circuit.state() == "open"
    with pytest.raises(CircuitOpen):
        call_with_retry(
            boom,
            timeout_seconds=1,
            max_retries=0,
            backoff_seconds=0.01,
            circuit=circuit,
        )


def test_model_timeout_is_enforced():
    circuit = CircuitBreaker(failure_threshold=5, reset_seconds=60)

    def hang():
        import time

        time.sleep(2)
        return "done"

    with pytest.raises(TimeoutError):
        call_with_retry(
            hang,
            timeout_seconds=0.2,
            max_retries=0,
            backoff_seconds=0.01,
            circuit=circuit,
        )


def test_live_verification_treats_host_and_prefix_as_same_rule():
    from app.execute.live import _same_rule
    from app.firewall.policy import AclRule, parse_acl_command

    expected = parse_acl_command(
        "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"
    )
    assert expected is not None
    read_back = AclRule(
        line=30,
        action="permit",
        proto="tcp",
        src="10.10.1.10/32",
        dst="10.20.1.50/32",
        port=443,
    )
    assert _same_rule(read_back, expected)
