"""Startup verification for the approval ledger and external anchor."""

from __future__ import annotations

from app.audit import store as audit_store
from app.audit.anchor import AnchorCheck, AnchorSink, check_against_anchor
from app.audit.keys import KeySet
from app.audit.ledger import verify_chain


async def verify_ledger_at_startup(
    conn,
    *,
    keyset: KeySet,
    anchor_sink: AnchorSink,
) -> tuple[AnchorCheck, str]:
    rows = await audit_store.list_approvals(conn)
    chain = verify_chain(rows, keyset.trusted)
    if not chain.ok:
        return (
            AnchorCheck(
                ok=False,
                reason=chain.reason or "ledger chain verification failed",
            ),
            chain.reason or "ledger chain verification failed",
        )

    anchor = check_against_anchor(rows, anchor_sink.latest(), keyset.trusted)
    if rows and not anchor.anchor_present:
        return (
            AnchorCheck(
                ok=False,
                reason=(
                    "The ledger contains records but no external anchor is configured; "
                    "deletion or rollback would be undetectable."
                ),
            ),
            "ledger has records but no external anchor is configured",
        )
    return anchor, anchor.reason
