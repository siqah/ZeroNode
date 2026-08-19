"""Append-only persistence for the approval ledger.

The append-only property is enforced by the database, not by the application: a
trigger rejects UPDATE and DELETE on the table, so even direct SQL access cannot
quietly rewrite history.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.audit.anchor import AnchorSink, seal_anchor
from app.audit.keys import KeySet, rotation_evidence
from app.audit.ledger import GENESIS_HASH, ApprovalRecord, SealedApproval, Signer

CREATE_APPROVALS = """
CREATE TABLE IF NOT EXISTS approvals (
    id BIGSERIAL PRIMARY KEY,
    thread_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    feedback TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    evidence JSONB NOT NULL,
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS approvals_thread_idx ON approvals (thread_id);

CREATE OR REPLACE FUNCTION approvals_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'approvals is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS approvals_no_mutate ON approvals;
CREATE TRIGGER approvals_no_mutate
BEFORE UPDATE OR DELETE ON approvals
FOR EACH ROW EXECUTE FUNCTION approvals_append_only();
"""

# Serialises appends so two concurrent approvals cannot claim the same predecessor.
CHAIN_LOCK = "SELECT pg_advisory_xact_lock(hashtext('zeronode_approvals'))"


async def ensure_approvals_table(conn: psycopg.AsyncConnection) -> None:
    await conn.execute(CREATE_APPROVALS)


async def _head(conn: psycopg.AsyncConnection) -> tuple[str, str, int]:
    """Return (last hash, last key_id, record count)."""
    async with conn.cursor() as cur:
        await cur.execute("SELECT hash, key_id FROM approvals ORDER BY id DESC LIMIT 1")
        row = await cur.fetchone()
        await cur.execute("SELECT count(*) FROM approvals")
        count_row = await cur.fetchone()
    count = int(count_row[0]) if count_row else 0
    if not row:
        return GENESIS_HASH, "", count
    return row[0], row[1], count


async def _insert(
    conn: psycopg.AsyncConnection, record: ApprovalRecord, sealed: SealedApproval
) -> None:
    await conn.execute(
        """
        INSERT INTO approvals (
            thread_id, decision, feedback, actor, actor_role,
            evidence, created_at, prev_hash, hash, signature, key_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            record.thread_id,
            record.decision,
            record.feedback,
            record.actor,
            record.actor_role,
            Json(record.evidence),
            record.created_at,
            record.prev_hash,
            sealed.hash,
            sealed.signature,
            sealed.key_id,
        ),
    )


async def append_approval(
    conn: psycopg.AsyncConnection,
    signer: Signer,
    *,
    thread_id: str,
    decision: str,
    feedback: str,
    actor: str,
    actor_role: str,
    evidence: dict[str, Any],
    sink: AnchorSink | None = None,
) -> SealedApproval:
    async with conn.transaction():
        await conn.execute(CHAIN_LOCK)
        prev_hash, _, count = await _head(conn)
        record = ApprovalRecord.now(
            thread_id=thread_id,
            decision=decision,
            feedback=feedback,
            actor=actor,
            actor_role=actor_role,
            evidence=evidence,
            prev_hash=prev_hash,
        )
        sealed = signer.seal(record)
        await _insert(conn, record, sealed)

    if sink is not None:
        sink.write(seal_anchor(sealed.hash, count + 1, signer))
    return sealed


async def ensure_rotation_record(
    conn: psycopg.AsyncConnection, keyset: KeySet, sink: AnchorSink | None = None
) -> SealedApproval | None:
    """Write a rotation marker when the active key differs from the last one used.

    Without it the key change is invisible in the ledger and an auditor cannot
    tell a rotation from an attempt to sign with a foreign key.
    """
    async with conn.transaction():
        await conn.execute(CHAIN_LOCK)
        prev_hash, last_key_id, count = await _head(conn)
        if not last_key_id or last_key_id == keyset.active.key_id:
            return None
        record = ApprovalRecord.now(
            thread_id="ledger",
            decision="key-rotation",
            feedback="",
            actor="system",
            actor_role="system",
            evidence=rotation_evidence(last_key_id, keyset.active.key_id),
            prev_hash=prev_hash,
        )
        sealed = keyset.active.seal(record)
        await _insert(conn, record, sealed)

    if sink is not None:
        sink.write(seal_anchor(sealed.hash, count + 1, keyset.active))
    return sealed


async def list_approvals(
    conn: psycopg.AsyncConnection, thread_id: str | None = None
) -> list[dict[str, Any]]:
    query = """
        SELECT id, thread_id, decision, feedback, actor, actor_role,
               evidence, created_at, prev_hash, hash, signature, key_id
        FROM approvals
    """
    params: tuple[Any, ...] = ()
    if thread_id:
        query += " WHERE thread_id = %s"
        params = (thread_id,)
    query += " ORDER BY id"

    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, params)
        return list(await cur.fetchall())
