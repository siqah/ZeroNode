"""Lease and run investigation jobs until interrupted."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import uuid
from typing import Any

from app.config import settings
from app.jobs.dispatcher import Dispatcher
from app.jobs.runner import InvestigationRunner
from app.jobs.store import Job
from app.observability import Metrics

logger = logging.getLogger(__name__)


def default_worker_id() -> str:
    configured = (settings.worker_id or "").strip()
    if configured:
        return configured
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


class Worker:
    def __init__(
        self,
        dispatcher: Dispatcher,
        runner: InvestigationRunner,
        *,
        worker_id: str | None = None,
        concurrency: int | None = None,
        lease_seconds: int | None = None,
        heartbeat_seconds: int | None = None,
        poll_seconds: float | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.runner = runner
        self.worker_id = worker_id or default_worker_id()
        self.concurrency = concurrency or settings.worker_concurrency
        self.lease_seconds = lease_seconds or settings.job_lease_seconds
        self.heartbeat_seconds = heartbeat_seconds or settings.job_heartbeat_seconds
        self.poll_seconds = poll_seconds or settings.worker_poll_seconds
        self.metrics = metrics
        self._stop = asyncio.Event()
        self._inflight: set[asyncio.Task[None]] = set()

    def request_stop(self) -> None:
        self._stop.set()

    async def run_forever(self) -> None:
        logger.info(
            "worker %s starting (concurrency=%d lease=%ds)",
            self.worker_id,
            self.concurrency,
            self.lease_seconds,
        )
        while not self._stop.is_set():
            await self.dispatcher.touch_worker(
                self.worker_id,
                concurrency=self.concurrency,
                meta={"pid": os.getpid()},
            )
            if self.metrics is not None:
                self.metrics.set_queue_depth(await self.dispatcher.depth())
            self._inflight = {task for task in self._inflight if not task.done()}
            while len(self._inflight) < self.concurrency and not self._stop.is_set():
                job = await self.dispatcher.claim(self.worker_id, self.lease_seconds)
                if job is None:
                    break
                task = asyncio.create_task(
                    self._run_claimed(job), name=f"job-{job.id}"
                )
                self._inflight.add(task)
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self.poll_seconds
                )
            except TimeoutError:
                pass
        if self._inflight:
            await asyncio.gather(*self._inflight, return_exceptions=True)
        logger.info("worker %s stopped", self.worker_id)

    async def _run_claimed(self, job: Job) -> None:
        heartbeat = asyncio.create_task(self._heartbeat_loop(job.id))
        try:
            await self.runner.run_job(job)
            await self.dispatcher.complete(job.id)
            logger.info("job %s (%s) succeeded", job.id, job.thread_id)
        except Exception as exc:
            delay = min(
                60.0,
                settings.model_retry_backoff_seconds * (2 ** max(job.attempts - 1, 0)),
            )
            status = await self.dispatcher.fail(
                job, error=str(exc), retry_delay_seconds=delay
            )
            logger.exception(
                "job %s (%s) failed -> %s: %s", job.id, job.thread_id, status, exc
            )
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass

    async def _heartbeat_loop(self, job_id: int) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_seconds)
            ok = await self.dispatcher.heartbeat(
                job_id, self.worker_id, self.lease_seconds
            )
            if not ok:
                logger.warning("lost lease on job %s", job_id)
                return


async def run_worker_process(app: Any) -> None:
    """Entry used by ``python -m app.jobs.worker`` after the FastAPI lifespan starts."""
    dispatcher = app.state.dispatcher
    runner = InvestigationRunner(app.state)
    worker = Worker(dispatcher, runner, metrics=getattr(app.state, "metrics", None))

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, worker.request_stop)
        except NotImplementedError:  # pragma: no cover - Windows
            pass

    await worker.run_forever()


def main() -> None:
    """Boot the same lifespan as the API, then poll forever."""
    from app.main import app
    from app.observability import configure_logging

    configure_logging(json_logs=settings.log_json, level=settings.log_level)

    async def _serve() -> None:
        async with app.router.lifespan_context(app):
            await run_worker_process(app)

    asyncio.run(_serve())


if __name__ == "__main__":
    main()
