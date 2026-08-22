from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.audit import store as audit_store
from app.audit.anchor import check_against_anchor
from app.audit.ledger import verify_chain
from app.auth.deps import require_role
from app.auth.models import Principal, Role

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


def _pool_or_503(request: Request):
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Approval ledger unavailable: the API has no database connection",
        )
    return pool


@router.get("/key")
async def signing_keys(request: Request, _: Principal = Depends(require_role(Role.VIEWER))):
    """Publish the public keys so the ledger can be verified independently."""
    keyset = request.app.state.keyset
    return {
        **keyset.describe(),
        "trusted_keys": keyset.trusted,
        "anchor": request.app.state.anchor_sink.describe(),
    }


@router.get("/approvals")
async def approvals(
    request: Request,
    thread_id: str | None = None,
    _: Principal = Depends(require_role(Role.VIEWER)),
):
    pool = _pool_or_503(request)
    async with pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        rows = await audit_store.list_approvals(conn, thread_id)
    return {"approvals": rows}


@router.get("/verify")
async def verify(request: Request, _: Principal = Depends(require_role(Role.VIEWER))):
    """Re-derive every hash and signature, then compare against the external anchor."""
    pool = _pool_or_503(request)
    keyset = request.app.state.keyset
    sink = request.app.state.anchor_sink
    async with pool.connection() as conn:
        await audit_store.ensure_approvals_table(conn)
        rows = await audit_store.list_approvals(conn)

    trusted = keyset.trusted
    report = verify_chain(rows, trusted)
    anchor = check_against_anchor(rows, sink.latest(), trusted)
    protected = anchor.ok and anchor.anchor_present
    return {
        "ok": report.ok and protected,
        "chain_ok": report.ok,
        "protected": protected,
        "records_checked": report.checked,
        "broken_at": report.broken_at,
        "reason": report.reason or anchor.reason,
        "anchor": {
            "ok": anchor.ok,
            "present": anchor.anchor_present,
            "protected": protected,
            "sink": sink.describe(),
            "anchored_count": anchor.anchored_count,
            "anchored_head": anchor.anchored_head,
        },
    }
