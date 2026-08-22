"""PostgreSQL-backed investigation job queue.

Jobs are leased with ``FOR UPDATE SKIP LOCKED`` so multiple workers can poll
without double-claiming. Delivery is at-least-once: callers must make resume
and device execution idempotent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

KIND_START = "start"
KIND_RESUME = "resume"

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_DEAD = "dead"

JobKind = str
JobStatus = str

CREATE_JOBS = (
    """
    CREATE TABLE IF NOT EXISTS investigation_jobs (
        id BIGSERIAL PRIMARY KEY,
        kind TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        dedupe_key TEXT NOT NULL UNIQUE,
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        status TEXT NOT NULL DEFAULT 'queued',
        attempts INT NOT NULL DEFAULT 0,
        max_attempts INT NOT NULL DEFAULT 5,
        available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        lease_owner TEXT,
        lease_expires_at TIMESTAMPTZ,
        last_error TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at TIMESTAMPTZ
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS investigation_jobs_poll_idx
        ON investigation_jobs (status, available_at, id)
    """,
    """
    CREATE INDEX IF NOT EXISTS investigation_jobs_thread_idx
        ON investigation_jobs (thread_id, created_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS worker_heartbeats (
        worker_id TEXT PRIMARY KEY,
        concurrency INT NOT NULL DEFAULT 1,
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        meta JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS execution_results (
        operation_key TEXT PRIMARY KEY,
        thread_id TEXT NOT NULL,
        result JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
)


@dataclass
class Job:
    id: int
    kind: str
    thread_id: str
    dedupe_key: str
    payload: dict[str, Any]
    status: str
    attempts: int
    max_attempts: int
    last_error: str = ""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _row(row: dict[str, Any]) -> Job:
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return Job(
        id=int(row["id"]),
        kind=str(row["kind"]),
        thread_id=str(row["thread_id"]),
        dedupe_key=str(row["dedupe_key"]),
        payload=dict(payload or {}),
        status=str(row["status"]),
        attempts=int(row["attempts"]),
        max_attempts=int(row["max_attempts"]),
        last_error=str(row.get("last_error") or ""),
    )


async def ensure_jobs_tables(conn: psycopg.AsyncConnection) -> None:
    for statement in CREATE_JOBS:
        await conn.execute(statement)


async def enqueue(
    conn: psycopg.AsyncConnection,
    *,
    kind: str,
    thread_id: str,
    dedupe_key: str,
    payload: dict[str, Any] | None = None,
    max_attempts: int = 5,
) -> tuple[int, bool]:
    """Insert a job. Returns ``(job_id, created)``; duplicates return the existing id."""
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            INSERT INTO investigation_jobs
                (kind, thread_id, dedupe_key, payload, max_attempts)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (dedupe_key) DO UPDATE
              SET dedupe_key = EXCLUDED.dedupe_key
            RETURNING id, (xmax = 0) AS created
            """,
            (kind, thread_id, dedupe_key, Jsonb(payload or {}), max_attempts),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row["id"]), bool(row["created"])


async def queue_depth(conn: psycopg.AsyncConnection) -> int:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT COUNT(*) FROM investigation_jobs
            WHERE status IN ('queued', 'running')
            """
        )
        row = await cur.fetchone()
    return int(row[0]) if row else 0


async def oldest_queued_age_seconds(conn: psycopg.AsyncConnection) -> float | None:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT EXTRACT(EPOCH FROM (now() - MIN(created_at)))
            FROM investigation_jobs
            WHERE status = 'queued'
            """
        )
        row = await cur.fetchone()
    if not row or row[0] is None:
        return None
    return float(row[0])


async def claim_next(
    conn: psycopg.AsyncConnection,
    *,
    worker_id: str,
    lease_seconds: int,
) -> Job | None:
    """Lease one ready job for ``worker_id``, or return None."""
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            WITH next_job AS (
                SELECT id FROM investigation_jobs
                WHERE status = 'queued'
                  AND available_at <= now()
                ORDER BY id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE investigation_jobs AS j
            SET status = 'running',
                attempts = j.attempts + 1,
                lease_owner = %s,
                lease_expires_at = now() + (%s || ' seconds')::interval,
                updated_at = now(),
                last_error = ''
            FROM next_job
            WHERE j.id = next_job.id
            RETURNING j.*
            """,
            (worker_id, str(lease_seconds)),
        )
        row = await cur.fetchone()
    return _row(row) if row else None


async def reclaim_expired(conn: psycopg.AsyncConnection) -> int:
    """Return expired running leases to the queue for another attempt."""
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE investigation_jobs
            SET status = 'queued',
                lease_owner = NULL,
                lease_expires_at = NULL,
                available_at = now(),
                updated_at = now(),
                last_error = CASE
                    WHEN last_error = '' THEN 'lease expired'
                    ELSE last_error
                END
            WHERE status = 'running'
              AND lease_expires_at IS NOT NULL
              AND lease_expires_at < now()
            """
        )
        return cur.rowcount or 0


async def heartbeat_job(
    conn: psycopg.AsyncConnection,
    *,
    job_id: int,
    worker_id: str,
    lease_seconds: int,
) -> bool:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE investigation_jobs
            SET lease_expires_at = now() + (%s || ' seconds')::interval,
                updated_at = now()
            WHERE id = %s
              AND status = 'running'
              AND lease_owner = %s
            """,
            (str(lease_seconds), job_id, worker_id),
        )
        return bool(cur.rowcount)


async def complete_job(conn: psycopg.AsyncConnection, job_id: int) -> None:
    await conn.execute(
        """
        UPDATE investigation_jobs
        SET status = 'succeeded',
            lease_owner = NULL,
            lease_expires_at = NULL,
            finished_at = now(),
            updated_at = now()
        WHERE id = %s
        """,
        (job_id,),
    )


async def fail_job(
    conn: psycopg.AsyncConnection,
    job: Job,
    *,
    error: str,
    retry_delay_seconds: float,
) -> str:
    """Mark a job failed and either requeue or dead-letter it.

    Returns the resulting status (``queued`` or ``dead``).
    """
    if job.attempts >= job.max_attempts:
        await conn.execute(
            """
            UPDATE investigation_jobs
            SET status = 'dead',
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = %s,
                finished_at = now(),
                updated_at = now()
            WHERE id = %s
            """,
            (error[:2000], job.id),
        )
        return STATUS_DEAD

    await conn.execute(
        """
        UPDATE investigation_jobs
        SET status = 'queued',
            lease_owner = NULL,
            lease_expires_at = NULL,
            last_error = %s,
            available_at = now() + (%s || ' seconds')::interval,
            updated_at = now()
        WHERE id = %s
        """,
        (error[:2000], str(retry_delay_seconds), job.id),
    )
    return STATUS_QUEUED


async def latest_job_for_thread(
    conn: psycopg.AsyncConnection, thread_id: str
) -> Job | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            SELECT * FROM investigation_jobs
            WHERE thread_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (thread_id,),
        )
        row = await cur.fetchone()
    return _row(row) if row else None


async def touch_worker(
    conn: psycopg.AsyncConnection,
    *,
    worker_id: str,
    concurrency: int,
    meta: dict[str, Any] | None = None,
) -> None:
    await conn.execute(
        """
        INSERT INTO worker_heartbeats (worker_id, concurrency, last_seen, meta)
        VALUES (%s, %s, now(), %s)
        ON CONFLICT (worker_id) DO UPDATE
          SET concurrency = EXCLUDED.concurrency,
              last_seen = now(),
              meta = EXCLUDED.meta
        """,
        (worker_id, concurrency, Jsonb(meta or {})),
    )


async def worker_health(
    conn: psycopg.AsyncConnection, *, stale_after_seconds: int
) -> dict[str, Any]:
    cutoff = _utcnow() - timedelta(seconds=stale_after_seconds)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            SELECT worker_id, concurrency, last_seen, meta
            FROM worker_heartbeats
            ORDER BY last_seen DESC
            """
        )
        rows = await cur.fetchall()
    live = [row for row in rows if row["last_seen"] and row["last_seen"] >= cutoff]
    return {
        "workers": len(rows),
        "live_workers": len(live),
        "stale_workers": len(rows) - len(live),
        "live": [
            {
                "worker_id": row["worker_id"],
                "concurrency": row["concurrency"],
                "last_seen": row["last_seen"].isoformat(),
            }
            for row in live
        ],
    }


async def get_execution_result(
    conn: psycopg.AsyncConnection, operation_key: str
) -> dict[str, Any] | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT result FROM execution_results WHERE operation_key = %s",
            (operation_key,),
        )
        row = await cur.fetchone()
    if row is None:
        return None
    result = row["result"]
    if isinstance(result, str):
        return dict(json.loads(result))
    return dict(result or {})


async def put_execution_result(
    conn: psycopg.AsyncConnection,
    *,
    operation_key: str,
    thread_id: str,
    result: dict[str, Any],
) -> None:
    await conn.execute(
        """
        INSERT INTO execution_results (operation_key, thread_id, result)
        VALUES (%s, %s, %s)
        ON CONFLICT (operation_key) DO NOTHING
        """,
        (operation_key, thread_id, Jsonb(result)),
    )
