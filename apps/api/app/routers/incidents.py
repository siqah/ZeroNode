from __future__ import annotations

import asyncio
import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from langgraph.types import Command
from pydantic import BaseModel, Field

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
async def trigger_investigation(body: TriggerBody, request: Request):
    graph = request.app.state.graph
    pool = request.app.state.pool
    config = _thread_config(body.ticket_id)
    initial = {
        "messages": [("user", f"New Alert: {body.description}")],
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
    return {"status": "Agent dispatched", "thread_id": body.ticket_id}


@router.get("/incidents")
async def list_incidents(request: Request):
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
async def get_incident_status(thread_id: str, request: Request):
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
    }


@router.post("/incidents/{thread_id}/resume")
async def resume_investigation(thread_id: str, body: ResumeBody, request: Request):
    graph = request.app.state.graph
    config = _thread_config(thread_id)
    snapshot = await graph.aget_state(config)
    nxt = tuple(snapshot.next or ())
    if "execute_change" not in nxt:
        raise HTTPException(
            status_code=409,
            detail="Incident is not awaiting approval",
        )
    async def _run() -> None:
        try:
            await graph.ainvoke(
                Command(
                    resume=True,
                    update={
                        "human_decision": body.decision,
                        "human_feedback": body.feedback,
                    },
                ),
                config,
            )
        except Exception:
            logger.exception("resume failed for %s", thread_id)

    asyncio.create_task(_run())
    return {"status": f"Graph resumed with decision: {body.decision}"}
