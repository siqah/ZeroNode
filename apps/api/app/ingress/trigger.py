from __future__ import annotations

import logging
import re

from fastapi import HTTPException, Request

from app.auth.models import Principal
from app.ingress.models import NormalizedIncidentTrigger, TriggerResult
from app.jobs.dispatcher import QueueFull
from app.outbound import NullTicketSink
from app.sanitize import fence_alert, sanitize
from app.store import incidents as incident_store

logger = logging.getLogger(__name__)

THREAD_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")


def _build_initial(trigger: NormalizedIncidentTrigger, description: str, flags: list[str]) -> dict:
    return {
        "messages": [("user", fence_alert(description))],
        "alert_flags": flags,
        "incident_id": trigger.thread_id,
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
        "operation_key": "",
        "topology_site": trigger.site.strip(),
        "alert_source": trigger.source,
        "alert_external_id": trigger.external_id,
    }


async def trigger_incident(
    request: Request,
    trigger: NormalizedIncidentTrigger,
    *,
    principal: Principal,
) -> TriggerResult:
    if trigger.action == "ignore":
        logger.info(
            "incident %s ignored from %s (%s): %s",
            trigger.thread_id or trigger.external_id,
            trigger.source,
            principal.subject,
            trigger.ignore_reason,
        )
        metrics = getattr(request.app.state, "metrics", None)
        if metrics is not None:
            metrics.observe_webhook(trigger.source, "ignored")
        return TriggerResult(
            status="ignored",
            thread_id=trigger.thread_id,
            source=trigger.source,
            ignore_reason=trigger.ignore_reason,
        )

    if not trigger.thread_id or not THREAD_ID_PATTERN.fullmatch(trigger.thread_id):
        raise HTTPException(
            status_code=422,
            detail="thread_id must match ^[A-Za-z0-9._:-]+$",
        )

    dispatcher = getattr(request.app.state, "dispatcher", None)
    if dispatcher is None:
        raise HTTPException(status_code=503, detail="Investigation queue unavailable")

    description, flags = sanitize(trigger.description)
    if flags:
        logger.warning(
            "incident %s: alert text flagged (%s) from %s",
            trigger.thread_id,
            ", ".join(flags),
            principal.subject,
        )
        metrics = getattr(request.app.state, "metrics", None)
        if metrics is not None:
            for flag in flags:
                metrics.observe_alert_flag(flag)

    initial = _build_initial(trigger, description, flags)
    pool = request.app.state.pool
    if pool is not None:
        async with pool.connection() as conn:
            await incident_store.ensure_incidents_table(conn)
            await incident_store.insert_incident(
                conn,
                trigger.thread_id,
                trigger.description,
                trigger.severity,
                trigger.site.strip(),
            )
    else:
        request.app.state.memory_incidents[trigger.thread_id] = {
            "thread_id": trigger.thread_id,
            "description": trigger.description,
            "severity": trigger.severity,
            "created_at": None,
        }

    try:
        job_id, created = await dispatcher.enqueue_start(
            trigger.thread_id, payload={"initial": initial}
        )
        deduped = not created
    except QueueFull as exc:
        metrics = getattr(request.app.state, "metrics", None)
        if metrics is not None:
            metrics.observe_webhook(trigger.source, "rejected")
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    tickets = getattr(request.app.state, "tickets", None) or NullTicketSink()
    await tickets.opened(trigger.thread_id, description, trigger.severity)
    logger.info(
        "incident %s triggered by %s via %s (job %s)",
        trigger.thread_id,
        principal.subject,
        trigger.source,
        job_id,
    )
    metrics = getattr(request.app.state, "metrics", None)
    if metrics is not None:
        metrics.observe_webhook(trigger.source, "deduped" if deduped else "dispatched")
    return TriggerResult(
        status="Agent dispatched",
        thread_id=trigger.thread_id,
        job_id=job_id,
        deduped=deduped,
        source=trigger.source,
    )
