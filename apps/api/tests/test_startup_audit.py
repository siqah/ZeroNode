"""Startup audit verification tests."""

from __future__ import annotations

import pytest

from app.audit import store as audit_store
from app.audit.anchor import NullAnchorSink
from app.audit.keys import KeySet
from app.audit.ledger import Signer
from app.audit.startup import verify_ledger_at_startup

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_startup_verifies_empty_ledger_without_anchor(postgres_pool):
    signer = Signer(Signer.generate_seed())
    async with postgres_pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        check, _reason = await verify_ledger_at_startup(
            conn,
            keyset=KeySet(active=signer),
            anchor_sink=NullAnchorSink(),
        )

    assert check.ok is True
    assert check.anchor_present is False


@pytest.mark.asyncio
async def test_startup_degradation_when_ledger_exists_without_anchor(postgres_pool):
    signer = Signer(Signer.generate_seed())
    async with postgres_pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        await audit_store.append_approval(
            conn,
            signer,
            thread_id="INC-START-1",
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
