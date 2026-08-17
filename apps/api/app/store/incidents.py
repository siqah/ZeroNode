from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row

CREATE_INCIDENTS = """
CREATE TABLE IF NOT EXISTS incidents (
    thread_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


async def ensure_incidents_table(conn: psycopg.AsyncConnection) -> None:
    await conn.execute(CREATE_INCIDENTS)


async def insert_incident(
    conn: psycopg.AsyncConnection,
    thread_id: str,
    description: str,
    severity: str,
) -> None:
    await conn.execute(
        """
        INSERT INTO incidents (thread_id, description, severity)
        VALUES (%s, %s, %s)
        ON CONFLICT (thread_id) DO UPDATE
          SET description = EXCLUDED.description, severity = EXCLUDED.severity
        """,
        (thread_id, description, severity),
    )


async def list_incidents(conn: psycopg.AsyncConnection) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            SELECT thread_id, description, severity, created_at
            FROM incidents
            ORDER BY created_at DESC
            """
        )
        rows = await cur.fetchall()
    return [
        {
            "thread_id": row["thread_id"],
            "description": row["description"],
            "severity": row["severity"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        }
        for row in rows
    ]
