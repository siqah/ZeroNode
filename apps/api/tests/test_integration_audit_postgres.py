"""Postgres-backed approval ledger and anchor integration tests."""

from __future__ import annotations

import pytest

from app.audit import store as audit_store
from app.audit.anchor import FileAnchorSink, NullAnchorSink, check_against_anchor
from app.audit.keys import KeySet
from app.audit.ledger import Signer, verify_chain
from app.audit.startup import verify_ledger_at_startup

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_append_approval_writes_anchor_and_verifies(postgres_pool, tmp_path):
    signer = Signer(Signer.generate_seed())
    sink = FileAnchorSink(tmp_path / "anchors.jsonl")
    async with postgres_pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        sealed = await audit_store.append_approval(
            conn,
            signer,
            thread_id="INC-AUD-1",
            decision="approve",
            feedback="looks good",
            actor="alice@example.com",
            actor_role="approver",
            evidence={"proposed_actions": []},
            sink=sink,
        )
        rows = await audit_store.list_approvals(conn)

    assert sealed.hash
    assert verify_chain(rows, KeySet(active=signer).trusted).ok is True
    anchor = sink.latest()
    assert anchor is not None
    assert anchor.record_count == 1
    assert check_against_anchor(rows, anchor, KeySet(active=signer).trusted).ok is True


@pytest.mark.asyncio
async def test_rotation_record_written_when_active_key_changes(postgres_pool, tmp_path):
    old = Signer(Signer.generate_seed())
    new = Signer(Signer.generate_seed())
    sink = FileAnchorSink(tmp_path / "anchors.jsonl")
    async with postgres_pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        await audit_store.append_approval(
            conn,
            old,
            thread_id="INC-AUD-2",
            decision="approve",
            feedback="",
            actor="alice@example.com",
            actor_role="approver",
            evidence={},
            sink=sink,
        )
        rotated = await audit_store.ensure_rotation_record(
            conn, KeySet(active=new, retired_public_keys=[old.public_key_b64]), sink=sink
        )
        rows = await audit_store.list_approvals(conn)

    assert rotated is not None
    assert rows[-1]["decision"] == "key-rotation"
    assert verify_chain(rows, KeySet(active=new, retired_public_keys=[old.public_key_b64]).trusted).ok


@pytest.mark.asyncio
async def test_startup_reports_missing_anchor_for_existing_ledger(postgres_pool):
    signer = Signer(Signer.generate_seed())
    async with postgres_pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        await audit_store.append_approval(
            conn,
            signer,
            thread_id="INC-AUD-3",
            decision="approve",
            feedback="",
            actor="alice@example.com",
            actor_role="approver",
            evidence={},
            sink=None,
        )
        check, reason = await verify_ledger_at_startup(
            conn,
            keyset=KeySet(active=signer),
            anchor_sink=NullAnchorSink(),
        )

    assert check.ok is False
    assert "no external anchor" in reason


@pytest.mark.asyncio
async def test_startup_detects_tampered_anchor(postgres_pool, tmp_path):
    from app.audit.anchor import seal_anchor

    signer = Signer(Signer.generate_seed())
    sink = FileAnchorSink(tmp_path / "anchors.jsonl")
    async with postgres_pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        await audit_store.append_approval(
            conn,
            signer,
            thread_id="INC-AUD-4",
            decision="approve",
            feedback="",
            actor="alice@example.com",
            actor_role="approver",
            evidence={},
            sink=sink,
        )
        sink.write(seal_anchor("0" * 64, 1, signer))
        check, _reason = await verify_ledger_at_startup(
            conn,
            keyset=KeySet(active=signer),
            anchor_sink=sink,
        )

    assert check.ok is False


@pytest.mark.asyncio
async def test_audit_verify_api_reports_chain_and_protection(postgres_pool, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.audit.anchor import FileAnchorSink
    from app.auth.models import Principal, Role
    from app.auth.tokens import issue_token
    from app.routers.audit import router as audit_router

    signer = Signer(Signer.generate_seed())
    sink = FileAnchorSink(tmp_path / "anchors.jsonl")
    async with postgres_pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        await audit_store.append_approval(
            conn,
            signer,
            thread_id="INC-AUD-6",
            decision="approve",
            feedback="",
            actor="alice@example.com",
            actor_role="approver",
            evidence={},
            sink=sink,
        )

    app = FastAPI()
    app.include_router(audit_router)
    app.state.pool = postgres_pool
    app.state.keyset = KeySet(active=signer)
    app.state.anchor_sink = sink
    app.state.jwt_secret = "test-secret-value-long-enough"
    token, _ = issue_token(Principal("viewer@example.com", Role.VIEWER), app.state.jwt_secret, 60)
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["chain_ok"] is True
    assert body["protected"] is True
    assert body["ok"] is True
