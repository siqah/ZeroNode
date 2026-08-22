"""Dispatcher surface: durable Postgres queue or an explicit in-memory fallback."""

from __future__ import annotations

import asyncio
import itertools
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

from psycopg_pool import AsyncConnectionPool

from app.jobs import store as job_store
from app.jobs.store import Job

logger = logging.getLogger(__name__)


class QueueFull(RuntimeError):
    """Raised when the configured job capacity would be exceeded."""


class Dispatcher(Protocol):
    async def enqueue_start(
        self, thread_id: str, *, payload: dict[str, Any] | None = None
    ) -> tuple[int, bool]: ...

    async def enqueue_resume(
        self,
        thread_id: str,
        *,
        approval_hash: str,
        payload: dict[str, Any],
    ) -> int: ...

    async def claim(self, worker_id: str, lease_seconds: int) -> Job | None: ...

    async def heartbeat(self, job_id: int, worker_id: str, lease_seconds: int) -> bool: ...

    async def complete(self, job_id: int) -> None: ...

    async def fail(
        self, job: Job, *, error: str, retry_delay_seconds: float
    ) -> str: ...

    async def reclaim_expired(self) -> int: ...

    async def touch_worker(
        self, worker_id: str, *, concurrency: int, meta: dict[str, Any] | None = None
    ) -> None: ...

    async def health(self, *, stale_after_seconds: int) -> dict[str, Any]: ...

    async def depth(self) -> int: ...

    async def latest_error(self, thread_id: str) -> str: ...

    async def get_execution(self, operation_key: str) -> dict[str, Any] | None: ...

    async def put_execution(
        self, operation_key: str, thread_id: str, result: dict[str, Any]
    ) -> None: ...


@dataclass
class PostgresDispatcher:
    pool: AsyncConnectionPool
    capacity: int
    max_attempts: int

    async def enqueue_start(
        self, thread_id: str, *, payload: dict[str, Any] | None = None
    ) -> tuple[int, bool]:
        return await self._enqueue(
            kind=job_store.KIND_START,
            thread_id=thread_id,
            dedupe_key=f"start:{thread_id}",
            payload=payload or {},
        )

    async def enqueue_resume(
        self,
        thread_id: str,
        *,
        approval_hash: str,
        payload: dict[str, Any],
    ) -> int:
        job_id, _created = await self._enqueue(
            kind=job_store.KIND_RESUME,
            thread_id=thread_id,
            dedupe_key=f"resume:{thread_id}:{approval_hash}",
            payload=payload,
        )
        return job_id

    async def _enqueue(
        self,
        *,
        kind: str,
        thread_id: str,
        dedupe_key: str,
        payload: dict[str, Any],
    ) -> tuple[int, bool]:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            depth = await job_store.queue_depth(conn)
            existing = None
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT id FROM investigation_jobs WHERE dedupe_key = %s",
                    (dedupe_key,),
                )
                existing = await cur.fetchone()
            if existing is None and depth >= self.capacity:
                raise QueueFull(
                    f"investigation queue is full ({depth}/{self.capacity})"
                )
            job_id, created = await job_store.enqueue(
                conn,
                kind=kind,
                thread_id=thread_id,
                dedupe_key=dedupe_key,
                payload=payload,
                max_attempts=self.max_attempts,
            )
        if created:
            logger.info("enqueued %s job %s for %s", kind, job_id, thread_id)
        else:
            logger.info("deduped %s job %s for %s", kind, job_id, thread_id)
        return job_id, created

    async def claim(self, worker_id: str, lease_seconds: int) -> Job | None:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            await job_store.reclaim_expired(conn)
            return await job_store.claim_next(
                conn, worker_id=worker_id, lease_seconds=lease_seconds
            )

    async def heartbeat(
        self, job_id: int, worker_id: str, lease_seconds: int
    ) -> bool:
        async with self.pool.connection() as conn:
            return await job_store.heartbeat_job(
                conn,
                job_id=job_id,
                worker_id=worker_id,
                lease_seconds=lease_seconds,
            )

    async def complete(self, job_id: int) -> None:
        async with self.pool.connection() as conn:
            await job_store.complete_job(conn, job_id)

    async def fail(
        self, job: Job, *, error: str, retry_delay_seconds: float
    ) -> str:
        async with self.pool.connection() as conn:
            return await job_store.fail_job(
                conn, job, error=error, retry_delay_seconds=retry_delay_seconds
            )

    async def reclaim_expired(self) -> int:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            return await job_store.reclaim_expired(conn)

    async def touch_worker(
        self, worker_id: str, *, concurrency: int, meta: dict[str, Any] | None = None
    ) -> None:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            await job_store.touch_worker(
                conn, worker_id=worker_id, concurrency=concurrency, meta=meta
            )

    async def health(self, *, stale_after_seconds: int) -> dict[str, Any]:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            depth = await job_store.queue_depth(conn)
            oldest = await job_store.oldest_queued_age_seconds(conn)
            workers = await job_store.worker_health(
                conn, stale_after_seconds=stale_after_seconds
            )
        return {
            "backend": "postgres",
            "depth": depth,
            "capacity": self.capacity,
            "oldest_queued_age_seconds": oldest,
            "saturated": depth >= self.capacity,
            **workers,
        }

    async def depth(self) -> int:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            return await job_store.queue_depth(conn)

    async def latest_error(self, thread_id: str) -> str:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            job = await job_store.latest_job_for_thread(conn, thread_id)
        if job is None:
            return ""
        if job.status == job_store.STATUS_DEAD:
            return job.last_error
        return ""

    async def get_execution(self, operation_key: str) -> dict[str, Any] | None:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            return await job_store.get_execution_result(conn, operation_key)

    async def put_execution(
        self, operation_key: str, thread_id: str, result: dict[str, Any]
    ) -> None:
        async with self.pool.connection() as conn:
            await job_store.ensure_jobs_tables(conn)
            await job_store.put_execution_result(
                conn,
                operation_key=operation_key,
                thread_id=thread_id,
                result=result,
            )


@dataclass
class _MemoryJob:
    id: int
    kind: str
    thread_id: str
    dedupe_key: str
    payload: dict[str, Any]
    status: str = job_store.STATUS_QUEUED
    attempts: int = 0
    max_attempts: int = 5
    last_error: str = ""
    available_at: float = 0.0
    lease_owner: str | None = None
    lease_expires_at: float | None = None


@dataclass
class InMemoryDispatcher:
    """Explicit non-durable fallback for local tests without Postgres."""

    capacity: int = 100
    max_attempts: int = 5
    _jobs: dict[int, _MemoryJob] = field(default_factory=dict)
    _by_key: dict[str, int] = field(default_factory=dict)
    _workers: dict[str, dict[str, Any]] = field(default_factory=dict)
    _executions: dict[str, dict[str, Any]] = field(default_factory=dict)
    _ids: itertools.count = field(default_factory=lambda: itertools.count(1))
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def enqueue_start(
        self, thread_id: str, *, payload: dict[str, Any] | None = None
    ) -> tuple[int, bool]:
        return await self._enqueue(
            kind=job_store.KIND_START,
            thread_id=thread_id,
            dedupe_key=f"start:{thread_id}",
            payload=payload or {},
        )

    async def enqueue_resume(
        self,
        thread_id: str,
        *,
        approval_hash: str,
        payload: dict[str, Any],
    ) -> int:
        job_id, _created = await self._enqueue(
            kind=job_store.KIND_RESUME,
            thread_id=thread_id,
            dedupe_key=f"resume:{thread_id}:{approval_hash}",
            payload=payload,
        )
        return job_id

    async def _enqueue(
        self,
        *,
        kind: str,
        thread_id: str,
        dedupe_key: str,
        payload: dict[str, Any],
    ) -> tuple[int, bool]:
        async with self._lock:
            if dedupe_key in self._by_key:
                return self._by_key[dedupe_key], False
            depth = sum(
                1
                for job in self._jobs.values()
                if job.status in (job_store.STATUS_QUEUED, job_store.STATUS_RUNNING)
            )
            if depth >= self.capacity:
                raise QueueFull(
                    f"investigation queue is full ({depth}/{self.capacity})"
                )
            job_id = next(self._ids)
            self._jobs[job_id] = _MemoryJob(
                id=job_id,
                kind=kind,
                thread_id=thread_id,
                dedupe_key=dedupe_key,
                payload=dict(payload),
                max_attempts=self.max_attempts,
            )
            self._by_key[dedupe_key] = job_id
            return job_id, True

    async def claim(self, worker_id: str, lease_seconds: int) -> Job | None:
        now = asyncio.get_running_loop().time()
        async with self._lock:
            for job in self._jobs.values():
                if (
                    job.status == job_store.STATUS_RUNNING
                    and job.lease_expires_at is not None
                    and job.lease_expires_at < now
                ):
                    job.status = job_store.STATUS_QUEUED
                    job.lease_owner = None
                    job.lease_expires_at = None
                    job.available_at = now
                    if not job.last_error:
                        job.last_error = "lease expired"
            for job in sorted(self._jobs.values(), key=lambda item: item.id):
                if (
                    job.status == job_store.STATUS_QUEUED
                    and job.available_at <= now
                ):
                    job.status = job_store.STATUS_RUNNING
                    job.attempts += 1
                    job.lease_owner = worker_id
                    job.lease_expires_at = now + lease_seconds
                    job.last_error = ""
                    return Job(
                        id=job.id,
                        kind=job.kind,
                        thread_id=job.thread_id,
                        dedupe_key=job.dedupe_key,
                        payload=dict(job.payload),
                        status=job.status,
                        attempts=job.attempts,
                        max_attempts=job.max_attempts,
                        last_error=job.last_error,
                    )
        return None

    async def heartbeat(
        self, job_id: int, worker_id: str, lease_seconds: int
    ) -> bool:
        now = asyncio.get_running_loop().time()
        async with self._lock:
            job = self._jobs.get(job_id)
            if (
                job is None
                or job.status != job_store.STATUS_RUNNING
                or job.lease_owner != worker_id
            ):
                return False
            job.lease_expires_at = now + lease_seconds
            return True

    async def complete(self, job_id: int) -> None:
        async with self._lock:
            job = self._jobs[job_id]
            job.status = job_store.STATUS_SUCCEEDED
            job.lease_owner = None
            job.lease_expires_at = None

    async def fail(
        self, job: Job, *, error: str, retry_delay_seconds: float
    ) -> str:
        now = asyncio.get_running_loop().time()
        async with self._lock:
            stored = self._jobs[job.id]
            stored.last_error = error[:2000]
            stored.lease_owner = None
            stored.lease_expires_at = None
            if stored.attempts >= stored.max_attempts:
                stored.status = job_store.STATUS_DEAD
                return job_store.STATUS_DEAD
            stored.status = job_store.STATUS_QUEUED
            stored.available_at = now + retry_delay_seconds
            return job_store.STATUS_QUEUED

    async def reclaim_expired(self) -> int:
        now = asyncio.get_running_loop().time()
        async with self._lock:
            count = 0
            for job in self._jobs.values():
                if (
                    job.status == job_store.STATUS_RUNNING
                    and job.lease_expires_at is not None
                    and job.lease_expires_at < now
                ):
                    job.status = job_store.STATUS_QUEUED
                    job.lease_owner = None
                    job.lease_expires_at = None
                    count += 1
            return count

    async def touch_worker(
        self, worker_id: str, *, concurrency: int, meta: dict[str, Any] | None = None
    ) -> None:
        async with self._lock:
            self._workers[worker_id] = {
                "concurrency": concurrency,
                "last_seen": asyncio.get_running_loop().time(),
                "meta": meta or {},
            }

    async def health(self, *, stale_after_seconds: int) -> dict[str, Any]:
        now = asyncio.get_running_loop().time()
        async with self._lock:
            live = [
                worker_id
                for worker_id, info in self._workers.items()
                if now - float(info["last_seen"]) <= stale_after_seconds
            ]
            depth = sum(
                1
                for job in self._jobs.values()
                if job.status in (job_store.STATUS_QUEUED, job_store.STATUS_RUNNING)
            )
        return {
            "backend": "memory",
            "depth": depth,
            "capacity": self.capacity,
            "oldest_queued_age_seconds": None,
            "saturated": depth >= self.capacity,
            "workers": len(self._workers),
            "live_workers": len(live),
            "stale_workers": len(self._workers) - len(live),
            "live": [{"worker_id": worker_id} for worker_id in live],
        }

    async def depth(self) -> int:
        async with self._lock:
            return sum(
                1
                for job in self._jobs.values()
                if job.status in (job_store.STATUS_QUEUED, job_store.STATUS_RUNNING)
            )

    async def latest_error(self, thread_id: str) -> str:
        async with self._lock:
            jobs = [
                job
                for job in self._jobs.values()
                if job.thread_id == thread_id
            ]
            if not jobs:
                return ""
            newest = max(jobs, key=lambda item: item.id)
            if newest.status == job_store.STATUS_DEAD:
                return newest.last_error
        return ""

    async def get_execution(self, operation_key: str) -> dict[str, Any] | None:
        async with self._lock:
            result = self._executions.get(operation_key)
            return dict(result) if result is not None else None

    async def put_execution(
        self, operation_key: str, thread_id: str, result: dict[str, Any]
    ) -> None:
        async with self._lock:
            self._executions.setdefault(operation_key, dict(result))
