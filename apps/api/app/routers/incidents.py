from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.audit import store as audit_store
from app.auth.deps import require_role
from app.auth.models import Principal, Role
from app.ingress.models import NormalizedIncidentTrigger
from app.ingress.trigger import trigger_incident
from app.jobs.dispatcher import QueueFull
from app.jobs.runner import thread_config
from app.outbound import NullTicketSink
from app.schedule import ChangeSchedule
from app.store import incidents as incident_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


class TriggerBody(BaseModel):
    ticket_id: str = Field(pattern=r"^[A-Za-z0-9._:-]+$", min_length=1)
    description: str = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"] = "high"
    site: str = Field(default="", max_length=128)


class ResumeBody(BaseModel):
    decision: Literal["approve", "reject"]
    feedback: str = ""
    # Break-glass for an outage that cannot wait for the next window. Admin only,
    # and the reason is sealed into the approval record.
    override_window: bool = False
    override_reason: str = ""


def _status_from_snapshot(values: dict, nxt: tuple) -> str:
    if "execute_change" in nxt:
        return "awaiting_approval"
    summary = (values.get("findings_summary") or "") if values else ""
    if summary.startswith("DRY-RUN") or summary.startswith("APPLIED"):
        return "resolved"
    if nxt:
        return "running"
    if values.get("messages"):
        return "completed"
    return "queued"


def _dispatcher(request: Request):
    dispatcher = getattr(request.app.state, "dispatcher", None)
    if dispatcher is None:
        raise HTTPException(
            status_code=503, detail="Investigation queue unavailable"
        )
    return dispatcher


async def _durable_error(request: Request, thread_id: str) -> str:
    dispatcher = getattr(request.app.state, "dispatcher", None)
    if dispatcher is None:
        return getattr(request.app.state, "graph_failures", {}).get(thread_id, "")
    return await dispatcher.latest_error(thread_id) or getattr(
        request.app.state, "graph_failures", {}
    ).get(thread_id, "")


@router.post("/incidents/trigger")
async def trigger_investigation(
    body: TriggerBody,
    request: Request,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
):
    trigger = NormalizedIncidentTrigger(
        thread_id=body.ticket_id,
        description=body.description,
        severity=body.severity,
        site=body.site.strip(),
        source="api",
    )
    result = await trigger_incident(request, trigger, principal=principal)
    return {
        "status": result.status,
        "thread_id": result.thread_id,
        "job_id": result.job_id,
        "deduped": result.deduped,
        "source": result.source,
    }


@router.get("/incidents")
async def list_incidents(
    request: Request,
    site: str = "",
    _: Principal = Depends(require_role(Role.VIEWER)),
):
    graph = request.app.state.graph
    pool = request.app.state.pool
    site_filter = site.strip()
    if pool is not None:
        async with pool.connection() as conn:
            await incident_store.ensure_incidents_table(conn)
            rows = await incident_store.list_incidents(conn, site=site_filter)
    else:
        rows = list(request.app.state.memory_incidents.values())

    enriched = []
    for row in rows:
        snapshot = await graph.aget_state(thread_config(row["thread_id"]))
        values = snapshot.values or {}
        nxt = tuple(snapshot.next or ())
        failure = await _durable_error(request, row["thread_id"])
        enriched.append(
            {
                **row,
                "status": "failed" if failure else _status_from_snapshot(values, nxt),
                "error": failure or None,
            }
        )
    return {"incidents": enriched}


@router.get("/incidents/{thread_id}/status")
async def get_incident_status(
    thread_id: str, request: Request, _: Principal = Depends(require_role(Role.VIEWER))
):
    graph = request.app.state.graph
    snapshot = await graph.aget_state(thread_config(thread_id))
    values = snapshot.values or {}
    nxt = tuple(snapshot.next or ())
    failure = await _durable_error(request, thread_id)
    if not values and not nxt:
        if failure:
            return {
                "thread_id": thread_id,
                "status": "failed",
                "error": failure,
                "current_node": None,
                "agent_summary": "",
                "topology_context": "",
                "zone_context": "",
                "verification": [],
                "proposed_actions": [],
                "reasoning_trace": [],
                "tool_log": [],
                "active_worker": "",
                "alert_flags": [],
                "execution": None,
                "execution_mode": _execution_mode(request),
                "change_window": _window_state(request),
            }
        raise HTTPException(status_code=404, detail="Unknown or still-queued incident")
    return {
        "thread_id": thread_id,
        "status": "failed" if failure else _status_from_snapshot(values, nxt),
        "error": failure or None,
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
        "execution": values.get("execution") or None,
        "execution_mode": _execution_mode(request),
        "change_window": _window_state(request),
    }


def _execution_mode(request: Request) -> str:
    executor = getattr(request.app.state, "executor", None)
    return executor.describe() if executor else "dry-run (no device is contacted)"


def _schedule(request: Request) -> ChangeSchedule:
    return getattr(request.app.state, "schedule", None) or ChangeSchedule()


def _window_state(request: Request) -> dict[str, Any]:
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
    dispatcher = _dispatcher(request)
    config = thread_config(thread_id)
    snapshot = await graph.aget_state(config)
    nxt = tuple(snapshot.next or ())
    if "execute_change" not in nxt:
        raise HTTPException(
            status_code=409,
            detail="Incident is not awaiting approval",
        )

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
    approval_hash = ""
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
            metrics = getattr(request.app.state, "metrics", None)
            if metrics is not None:
                created_at = await incident_store.get_created_at(conn, thread_id)
                if created_at is not None:
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=UTC)
                    latency = max(
                        0.0,
                        (datetime.now(UTC) - created_at).total_seconds(),
                    )
                    metrics.observe_approval_latency(latency)
        approval_hash = sealed.hash
        receipt = {
            "hash": sealed.hash,
            "key_id": sealed.key_id,
            "recorded_at": sealed.record.created_at,
        }
    elif getattr(request.app.state, "auth_enabled", True):
        raise HTTPException(
            status_code=503,
            detail="Approval ledger unavailable; refusing to act on an unrecorded decision",
        )
    else:
        approval_hash = f"memory:{thread_id}:{body.decision}"
        logger.warning(
            "auth disabled and no ledger: %s on %s is NOT being recorded",
            body.decision,
            thread_id,
        )

    try:
        job_id = await dispatcher.enqueue_resume(
            thread_id,
            approval_hash=approval_hash,
            payload={
                "decision": body.decision,
                "feedback": body.feedback,
                "actor": principal.subject,
                "actor_role": principal.role.value,
                "operation_key": approval_hash,
            },
        )
    except QueueFull as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    verb = "approved" if body.decision == "approve" else "rejected"
    logger.info("%s %s %s (job %s)", principal.subject, verb, thread_id, job_id)
    tickets = getattr(request.app.state, "tickets", None) or NullTicketSink()
    await tickets.commented(
        thread_id,
        f"{principal.subject} {verb} the proposed change."
        + (f" Note: {body.feedback}" if body.feedback else "")
        + (f" Change window overridden: {override['reason']}" if override else "")
        + (f" Ledger record {receipt['hash'][:16]}." if receipt else ""),
        {"event": f"approval.{body.decision}", "actor": principal.subject},
    )
    return {
        "status": f"Graph resumed with decision: {body.decision}",
        "actor": principal.subject,
        "receipt": receipt,
        "job_id": job_id,
    }
