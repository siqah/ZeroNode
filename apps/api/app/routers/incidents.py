from __future__ import annotations

import asyncio
import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from langgraph.types import Command
from pydantic import BaseModel, Field

from app.audit import store as audit_store
from app.auth.deps import require_role
from app.auth.models import Principal, Role
from app.sanitize import fence_alert, sanitize
from app.schedule import ChangeSchedule
from app.store import incidents as incident_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


class TriggerBody(BaseModel):
    ticket_id: str = Field(pattern=r"^[A-Za-z0-9._:-]+$", min_length=1)
    description: str = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"] = "high"


class ResumeBody(BaseModel):
    decision: Literal["approve", "reject"]
    feedback: str = ""
    # Break-glass for an outage that cannot wait for the next window. Admin only,
    # and the reason is sealed into the approval record.
    override_window: bool = False
    override_reason: str = ""


def _thread_config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}, "recursion_limit": 16}


def _status_from_snapshot(values: dict, nxt: tuple) -> str:
    if "execute_change" in nxt:
        return "awaiting_approval"
    summary = (values.get("findings_summary") or "") if values else ""
    if summary.startswith("DRY-RUN"):
        return "resolved"
    if nxt:
        return "running"
    if values.get("messages"):
        return "completed"
    return "queued"


@router.post("/incidents/trigger")
async def trigger_investigation(
    body: TriggerBody,
    request: Request,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
):
    graph = request.app.state.graph
    pool = request.app.state.pool
    config = _thread_config(body.ticket_id)

    # A webhook body is attacker-influenced text that lands in the same context
    # as the system prompt, so it is cleaned and fenced before the agent sees it.
    description, flags = sanitize(body.description)
    if flags:
        logger.warning(
            "incident %s: alert text flagged (%s) from %s",
            body.ticket_id,
            ", ".join(flags),
            principal.subject,
        )

    initial = {
        "messages": [("user", fence_alert(description))],
        "alert_flags": flags,
        "incident_id": body.ticket_id,
        "active_worker": "",
        "findings_summary": "",
        "pending_actions": [],
        "topology_context": "",
        "zone_context": "",
        "denied_flows": [],
        "verification": [],
        "verify_attempts": 0,
        "reasoning_trace": [],
        "tool_log": [],
        "task_brief": "",
        "human_decision": "",
        "human_feedback": "",
        "human_actor": "",
    }
    if pool is not None:
        async with pool.connection() as conn:
            await incident_store.ensure_incidents_table(conn)
            await incident_store.insert_incident(
                conn, body.ticket_id, body.description, body.severity
            )
    else:
        request.app.state.memory_incidents[body.ticket_id] = {
            "thread_id": body.ticket_id,
            "description": body.description,
            "severity": body.severity,
            "created_at": None,
        }

    async def _run() -> None:
        try:
            await graph.ainvoke(initial, config)
        except Exception:
            logger.exception("graph failed for %s", body.ticket_id)

    asyncio.create_task(_run())
    logger.info("incident %s triggered by %s", body.ticket_id, principal.subject)
    return {"status": "Agent dispatched", "thread_id": body.ticket_id}


@router.get("/incidents")
async def list_incidents(
    request: Request, _: Principal = Depends(require_role(Role.VIEWER))
):
    graph = request.app.state.graph
    pool = request.app.state.pool
    if pool is not None:
        async with pool.connection() as conn:
            await incident_store.ensure_incidents_table(conn)
            rows = await incident_store.list_incidents(conn)
    else:
        rows = list(request.app.state.memory_incidents.values())

    enriched = []
    for row in rows:
        snapshot = await graph.aget_state(_thread_config(row["thread_id"]))
        values = snapshot.values or {}
        nxt = tuple(snapshot.next or ())
        enriched.append({**row, "status": _status_from_snapshot(values, nxt)})
    return {"incidents": enriched}


@router.get("/incidents/{thread_id}/status")
async def get_incident_status(
    thread_id: str, request: Request, _: Principal = Depends(require_role(Role.VIEWER))
):
    graph = request.app.state.graph
    snapshot = await graph.aget_state(_thread_config(thread_id))
    values = snapshot.values or {}
    nxt = tuple(snapshot.next or ())
    if not values and not nxt:
        raise HTTPException(status_code=404, detail="Unknown or still-queued incident")
    return {
        "thread_id": thread_id,
        "status": _status_from_snapshot(values, nxt),
        "current_node": nxt[0] if nxt else None,
        "agent_summary": values.get("findings_summary", ""),
        "topology_context": values.get("topology_context", ""),
        "zone_context": values.get("zone_context", ""),
        "verification": values.get("verification", []),
        "proposed_actions": values.get("pending_actions") or [],
        "reasoning_trace": values.get("reasoning_trace") or [],
        "tool_log": values.get("tool_log") or [],
        "active_worker": values.get("active_worker", ""),
        "alert_flags": values.get("alert_flags") or [],
        "change_window": _window_state(request),
    }


def _schedule(request: Request) -> ChangeSchedule:
    return getattr(request.app.state, "schedule", None) or ChangeSchedule()


def _window_state(request: Request) -> dict[str, Any]:
    """Shown alongside the proposal so the window is visible before, not after."""
    schedule = _schedule(request)
    decision = schedule.evaluate()
    return {
        "open": decision.open,
        "reason": decision.reason,
        "next_open": decision.next_open,
        "policy": schedule.describe(),
    }


@router.post("/incidents/{thread_id}/resume")
async def resume_investigation(
    thread_id: str,
    body: ResumeBody,
    request: Request,
    principal: Principal = Depends(require_role(Role.APPROVER, human_only=True, mfa=True)),
):
    graph = request.app.state.graph
    config = _thread_config(thread_id)
    snapshot = await graph.aget_state(config)
    nxt = tuple(snapshot.next or ())
    if "execute_change" not in nxt:
        raise HTTPException(
            status_code=409,
            detail="Incident is not awaiting approval",
        )

    # Rejecting is always safe, so only approvals answer to the change window.
    window = _schedule(request).evaluate()
    override: dict[str, Any] | None = None
    if body.decision == "approve" and not window.open:
        if not body.override_window:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Change blocked: {window.reason}."
                    + (f" Next window opens {window.next_open}." if window.next_open else "")
                    + " An admin can override with a reason if this cannot wait."
                ),
            )
        if principal.role != Role.ADMIN:
            raise HTTPException(
                status_code=403,
                detail=f"Change blocked: {window.reason}. Only an admin can override it.",
            )
        if len(body.override_reason.strip()) < 10:
            raise HTTPException(
                status_code=422,
                detail="An override needs a written reason; it is kept in the approval record.",
            )
        override = {"reason": body.override_reason.strip(), "window": window.reason}
        logger.warning(
            "%s overrode the change window on %s: %s",
            principal.subject,
            thread_id,
            body.override_reason.strip(),
        )

    values = snapshot.values or {}
    evidence = {
        "proposed_actions": values.get("pending_actions") or [],
        "verification": values.get("verification") or [],
        "denied_flows": values.get("denied_flows") or [],
        "agent_summary": values.get("findings_summary", ""),
        "topology_context": values.get("topology_context", ""),
        "alert_flags": values.get("alert_flags") or [],
        "change_window": {"open": window.open, "reason": window.reason},
        "window_override": override,
    }

    pool = getattr(request.app.state, "pool", None)
    receipt: dict[str, Any] | None = None
    if pool is not None:
        async with pool.connection() as conn:
            await audit_store.ensure_approvals_table(conn)
            sealed = await audit_store.append_approval(
                conn,
                request.app.state.keyset.active,
                thread_id=thread_id,
                decision=body.decision,
                feedback=body.feedback,
                actor=principal.subject,
                actor_role=principal.role.value,
                evidence=evidence,
                sink=request.app.state.anchor_sink,
            )
        receipt = {
            "hash": sealed.hash,
            "key_id": sealed.key_id,
            "recorded_at": sealed.record.created_at,
        }
    elif getattr(request.app.state, "auth_enabled", True):
        # An approval that cannot be recorded is an approval nobody can be held to.
        raise HTTPException(
            status_code=503,
            detail="Approval ledger unavailable; refusing to act on an unrecorded decision",
        )
    else:
        logger.warning(
            "auth disabled and no ledger: %s on %s is NOT being recorded",
            body.decision,
            thread_id,
        )

    async def _run() -> None:
        try:
            await graph.ainvoke(
                Command(
                    resume=True,
                    update={
                        "human_decision": body.decision,
                        "human_feedback": body.feedback,
                        "human_actor": principal.subject,
                    },
                ),
                config,
            )
        except Exception:
            logger.exception("resume failed for %s", thread_id)

    asyncio.create_task(_run())
    logger.info("%s %sd %s", principal.subject, body.decision, thread_id)
    return {
        "status": f"Graph resumed with decision: {body.decision}",
        "actor": principal.subject,
        "receipt": receipt,
    }
