from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row

CREATE_INCIDENTS = """
CREATE TABLE IF NOT EXISTS incidents (
    thread_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    site TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


async def ensure_incidents_table(conn: psycopg.AsyncConnection) -> None:
    await conn.execute(CREATE_INCIDENTS)
    await conn.execute(
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS site TEXT NOT NULL DEFAULT ''"
    )


async def insert_incident(
    conn: psycopg.AsyncConnection,
    thread_id: str,
    description: str,
    severity: str,
    site: str = "",
) -> None:
    await conn.execute(
        """
        INSERT INTO incidents (thread_id, description, severity, site)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (thread_id) DO UPDATE
          SET description = EXCLUDED.description,
              severity = EXCLUDED.severity,
              site = EXCLUDED.site
        """,
        (thread_id, description, severity, site),
    )


async def get_created_at(conn: psycopg.AsyncConnection, thread_id: str):
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT created_at FROM incidents WHERE thread_id = %s",
            (thread_id,),
        )
        row = await cur.fetchone()
    return row[0] if row else None


async def list_incidents(conn: psycopg.AsyncConnection, *, site: str = "") -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        if site:
            await cur.execute(
                """
                SELECT thread_id, description, severity, site, created_at
                FROM incidents
                WHERE site = %s
                ORDER BY created_at DESC
                """,
                (site,),
            )
        else:
            await cur.execute(
                """
                SELECT thread_id, description, severity, site, created_at
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
            "site": row.get("site") or "",
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        }
        for row in rows
    ]
