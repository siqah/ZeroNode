from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.auth.models import Role

# One statement per entry. The pool prepares every statement, and a prepared
# statement cannot carry more than one command, so a single script would fail
# on a pooled connection while working on a plain one.
CREATE_USERS = (
    """
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ",
)

USER_COLUMNS = (
    "email, password_hash, role, active, totp_secret, totp_enabled, "
    "failed_attempts, locked_until"
)


async def ensure_users_table(conn: psycopg.AsyncConnection) -> None:
    for statement in CREATE_USERS:
        await conn.execute(statement)


async def get_user(conn: psycopg.AsyncConnection, email: str) -> dict[str, Any] | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            f"SELECT {USER_COLUMNS} FROM users WHERE email = %s",
            (email.lower(),),
        )
        return await cur.fetchone()


async def register_failure(
    conn: psycopg.AsyncConnection, email: str, threshold: int, lock_minutes: int
) -> int:
    """Count a failed attempt and lock the account once the threshold is hit.

    Returns the new failure count. Locking is stored rather than held in memory
    so it survives a restart and applies across replicas.
    """
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE users
               SET failed_attempts = failed_attempts + 1,
                   locked_until = CASE
                       WHEN failed_attempts + 1 >= %s
                       THEN now() + make_interval(mins => %s)
                       ELSE locked_until
                   END
             WHERE email = %s
            RETURNING failed_attempts
            """,
            (threshold, lock_minutes, email.lower()),
        )
        row = await cur.fetchone()
    return int(row[0]) if row else 0


async def clear_failures(conn: psycopg.AsyncConnection, email: str) -> None:
    await conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = %s",
        (email.lower(),),
    )


async def set_totp_secret(conn: psycopg.AsyncConnection, email: str, secret: str) -> None:
    await conn.execute(
        "UPDATE users SET totp_secret = %s, totp_enabled = FALSE WHERE email = %s",
        (secret, email.lower()),
    )


async def set_totp_enabled(conn: psycopg.AsyncConnection, email: str, enabled: bool) -> None:
    await conn.execute(
        "UPDATE users SET totp_enabled = %s, totp_secret = CASE WHEN %s THEN totp_secret "
        "ELSE '' END WHERE email = %s",
        (enabled, enabled, email.lower()),
    )


async def upsert_user(
    conn: psycopg.AsyncConnection, email: str, password_hash: str, role: Role
) -> None:
    await conn.execute(
        """
        INSERT INTO users (email, password_hash, role)
        VALUES (%s, %s, %s)
        ON CONFLICT (email) DO UPDATE
          SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
        """,
        (email.lower(), password_hash, role.value),
    )


async def create_if_absent(
    conn: psycopg.AsyncConnection, email: str, password_hash: str, role: Role
) -> bool:
    """Create a user only if the email is new. Returns True when one was created."""
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO users (email, password_hash, role)
            VALUES (%s, %s, %s)
            ON CONFLICT (email) DO NOTHING
            """,
            (email.lower(), password_hash, role.value),
        )
        return cur.rowcount > 0


async def list_users(conn: psycopg.AsyncConnection) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT email, role, active, created_at, totp_enabled, locked_until "
            "FROM users ORDER BY email"
        )
        rows = await cur.fetchall()
    return [
        {
            "email": row["email"],
            "role": row["role"],
            "active": row["active"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "mfa_enabled": row["totp_enabled"],
            "locked_until": row["locked_until"].isoformat() if row["locked_until"] else None,
        }
        for row in rows
    ]
