"""Run one investigation job against the compiled LangGraph."""

from __future__ import annotations

import logging
from typing import Any

from langgraph.types import Command

from app.audit import store as audit_store
from app.auth.models import Principal, Role
from app.inference.errors import ModelBudgetExceeded
from app.jobs.store import KIND_RESUME, KIND_START, Job
from app.observability import bind_correlation, clear_correlation, span, timed
from app.outbound import NullNotifier, NullTicketSink, pending_approval_message
from app.schedule import ChangeSchedule

logger = logging.getLogger(__name__)


def thread_config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}, "recursion_limit": 16}


class InvestigationRunner:
    """Shared by the API (in-memory fallback) and the durable worker process."""

    def __init__(self, app_state: Any) -> None:
        self.state = app_state

    @property
    def graph(self):
        return self.state.graph

    def tickets(self):
        return getattr(self.state, "tickets", None) or NullTicketSink()

    def notifier(self):
        return getattr(self.state, "notifier", None) or NullNotifier()

    def schedule(self) -> ChangeSchedule:
        return getattr(self.state, "schedule", None) or ChangeSchedule()

    def metrics(self):
        return getattr(self.state, "metrics", None)

    async def run_job(self, job: Job) -> None:
        bind_correlation(
            thread_id=job.thread_id,
            job_id=str(job.id),
            attempt=str(job.attempts),
            kind=job.kind,
        )
        metrics = self.metrics()
        with timed() as elapsed, span(
            f"job.{job.kind}", thread_id=job.thread_id, job_id=str(job.id)
        ):
            try:
                if job.kind == KIND_START:
                    await self._run_start(job)
                elif job.kind == KIND_RESUME:
                    await self._run_resume(job)
                else:
                    raise RuntimeError(f"unknown job kind {job.kind!r}")
                if metrics is not None:
                    metrics.observe_job(job.kind, "succeeded", elapsed[0])
            except Exception:
                if metrics is not None:
                    metrics.observe_job(job.kind, "failed", elapsed[0])
                raise
            finally:
                clear_correlation()

    async def _run_start(self, job: Job) -> None:
        initial = job.payload.get("initial")
        if not isinstance(initial, dict):
            raise RuntimeError("start job is missing initial state")
        await self._invoke_graph(job.thread_id, initial)
        await self.notify_if_waiting(job.thread_id)
        await self.close_if_finished(job.thread_id)

    async def _invoke_graph(self, thread_id: str, payload) -> None:
        settings = getattr(self.state, "settings", None)
        budget = float(getattr(settings, "model_incident_budget_seconds", 0) or 0)
        with timed() as elapsed:
            await self.graph.ainvoke(payload, thread_config(thread_id))
        if budget > 0 and elapsed[0] > budget:
            metrics = self.metrics()
            if metrics is not None:
                metrics.observe_budget_exceeded("incident")
            raise ModelBudgetExceeded(
                f"investigation {thread_id} exceeded model incident budget "
                f"({elapsed[0]:.1f}s > {budget:.1f}s)"
            )

    async def _run_resume(self, job: Job) -> None:
        payload = job.payload
        decision = str(payload.get("decision") or "")
        feedback = str(payload.get("feedback") or "")
        actor = str(payload.get("actor") or "")
        operation_key = str(payload.get("operation_key") or "")
        warm = getattr(self.state, "warm_execution", None)
        if callable(warm) and operation_key:
            await warm(operation_key)
        await self._invoke_graph(
            job.thread_id,
            Command(
                resume=True,
                update={
                    "human_decision": decision,
                    "human_feedback": feedback,
                    "human_actor": actor,
                    "operation_key": operation_key,
                },
            ),
        )
        principal = Principal(
            subject=actor or "system",
            role=Role(payload.get("actor_role") or Role.APPROVER.value),
            kind="user",
        )
        await self.record_execution(job.thread_id, principal)
        await self.notify_if_waiting(job.thread_id)
        await self.close_if_finished(job.thread_id)

    async def notify_if_waiting(self, thread_id: str) -> None:
        snapshot = await self.graph.aget_state(thread_config(thread_id))
        if "execute_change" not in tuple(snapshot.next or ()):
            return
        values = snapshot.values or {}
        window = self.schedule().evaluate()
        from app.config import settings

        text = pending_approval_message(
            thread_id,
            values.get("pending_actions") or [],
            settings.dashboard_url,
            window_reason="" if window.open else window.reason,
            alert_flags=values.get("alert_flags") or [],
        )
        await self.notifier().send(
            text, {"incident": thread_id, "event": "approval.pending"}
        )
        await self.tickets().commented(
            thread_id, text, {"event": "approval.pending", "state": "awaiting_approval"}
        )

    async def close_if_finished(self, thread_id: str) -> None:
        snapshot = await self.graph.aget_state(thread_config(thread_id))
        if tuple(snapshot.next or ()):
            return
        values = snapshot.values or {}
        await self.tickets().closed(
            thread_id,
            values.get("findings_summary")
            or "The investigation finished with no summary.",
        )

    async def record_execution(self, thread_id: str, principal: Principal) -> None:
        pool = getattr(self.state, "pool", None)
        if pool is None:
            return
        snapshot = await self.graph.aget_state(thread_config(thread_id))
        execution = (snapshot.values or {}).get("execution")
        if not execution or execution.get("state") == "logged":
            return
        metrics = self.metrics()
        if metrics is not None:
            metrics.observe_execution(str(execution.get("state")))
        try:
            async with pool.connection() as conn:
                await audit_store.append_approval(
                    conn,
                    self.state.keyset.active,
                    thread_id=thread_id,
                    decision=f"execution:{execution.get('state')}",
                    feedback="",
                    actor="system",
                    actor_role="system",
                    evidence={
                        "execution": execution,
                        "on_behalf_of": principal.subject,
                    },
                    sink=self.state.anchor_sink,
                )
        except Exception:
            logger.exception("could not record the execution of %s", thread_id)

        state = str(execution.get("state"))
        narrative = " ".join(execution.get("lines") or []) or state
        await self.tickets().commented(
            thread_id,
            f"Execution {state}: {narrative}",
            {"event": f"execution.{state}"},
        )
        if state in ("rollback_failed", "refused"):
            logger.error("%s on %s: %s", state, thread_id, narrative)
            await self.notifier().send(
                f"ZeroNode {thread_id}: execution {state}. {narrative}",
                {"incident": thread_id, "event": f"execution.{state}"},
            )
