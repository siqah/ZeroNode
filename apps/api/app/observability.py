"""Structured logging, Prometheus metrics, and optional OpenTelemetry."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_correlation: ContextVar[dict[str, str] | None] = ContextVar(
    "zeronode_correlation", default=None
)

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )
except ImportError:  # pragma: no cover - optional until installed
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    CollectorRegistry = None  # type: ignore[assignment,misc]
    Counter = Gauge = Histogram = generate_latest = None  # type: ignore[assignment]


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        payload.update(_correlation.get() or {})
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(*, json_logs: bool, level: str) -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    handler = logging.StreamHandler()
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
    root.handlers.clear()
    root.addHandler(handler)


def bind_correlation(**fields: str) -> None:
    current = dict(_correlation.get() or {})
    current.update({key: value for key, value in fields.items() if value})
    _correlation.set(current)


def clear_correlation() -> None:
    _correlation.set({})


class Metrics:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled and Counter is not None
        self.registry = CollectorRegistry() if self.enabled else None
        if not self.enabled:
            return
        assert Counter is not None and Gauge is not None and Histogram is not None
        self.jobs_total = Counter(
            "zeronode_jobs_total",
            "Investigation jobs by kind and outcome",
            ["kind", "outcome"],
            registry=self.registry,
        )
        self.job_duration = Histogram(
            "zeronode_job_duration_seconds",
            "Wall time spent running an investigation job",
            ["kind"],
            registry=self.registry,
        )
        self.model_calls = Counter(
            "zeronode_model_calls_total",
            "Model invocations by outcome",
            ["outcome"],
            registry=self.registry,
        )
        self.model_latency = Histogram(
            "zeronode_model_latency_seconds",
            "Model call latency",
            registry=self.registry,
        )
        self.node_duration = Histogram(
            "zeronode_graph_node_duration_seconds",
            "Graph node wall time",
            ["node"],
            registry=self.registry,
        )
        self.approval_latency = Histogram(
            "zeronode_approval_latency_seconds",
            "Time from trigger to approval resume",
            registry=self.registry,
        )
        self.execution_total = Counter(
            "zeronode_execution_total",
            "Device execution outcomes",
            ["state"],
            registry=self.registry,
        )
        self.queue_depth = Gauge(
            "zeronode_queue_depth",
            "Queued plus running investigation jobs",
            registry=self.registry,
        )
        self.circuit_state = Gauge(
            "zeronode_inference_circuit_open",
            "1 when the inference circuit is open",
            registry=self.registry,
        )
        self.inference_fallback = Counter(
            "zeronode_inference_fallback_total",
            "Turns where the graph advanced without a valid model tool call",
            ["node", "reason"],
            registry=self.registry,
        )
        self.budget_exceeded = Counter(
            "zeronode_model_budget_exceeded_total",
            "Investigations or nodes that exceeded a latency budget",
            ["scope"],
            registry=self.registry,
        )
        self.webhook_requests = Counter(
            "zeronode_webhook_requests_total",
            "Inbound webhook requests by source and outcome",
            ["source", "outcome"],
            registry=self.registry,
        )
        self.alert_flags = Counter(
            "zeronode_alert_flags_total",
            "Sanitized alert steering flags observed at ingress",
            ["flag"],
            registry=self.registry,
        )
        self._fallback_total = 0
        self._parse_error_total = 0
        self._model_calls_total = 0

    def observe_job(self, kind: str, outcome: str, seconds: float) -> None:
        if not self.enabled:
            return
        self.jobs_total.labels(kind=kind, outcome=outcome).inc()
        self.job_duration.labels(kind=kind).observe(seconds)

    def observe_model(self, outcome: str, seconds: float) -> None:
        self._model_calls_total += 1
        if not self.enabled:
            return
        self.model_calls.labels(outcome=outcome).inc()
        self.model_latency.observe(seconds)

    def observe_inference_fallback(self, node: str, reason: str) -> None:
        """Record an inferred turn or parse error (Phase 4 quality signal)."""
        self._fallback_total += 1
        if reason == "parse_error":
            self._parse_error_total += 1
        if not self.enabled:
            return
        self.inference_fallback.labels(node=node, reason=reason).inc()

    def observe_budget_exceeded(self, scope: str) -> None:
        if not self.enabled:
            return
        self.budget_exceeded.labels(scope=scope).inc()

    def observe_webhook(self, source: str, outcome: str) -> None:
        if not self.enabled:
            return
        self.webhook_requests.labels(source=source, outcome=outcome).inc()

    def observe_alert_flag(self, flag: str) -> None:
        if not self.enabled:
            return
        self.alert_flags.labels(flag=flag).inc()

    def observe_node(self, node: str, seconds: float) -> None:
        if not self.enabled:
            return
        self.node_duration.labels(node=node).observe(seconds)

    def observe_execution(self, state: str) -> None:
        if not self.enabled:
            return
        self.execution_total.labels(state=state).inc()

    def observe_approval_latency(self, seconds: float) -> None:
        if not self.enabled:
            return
        self.approval_latency.observe(seconds)

    def set_queue_depth(self, depth: int) -> None:
        if not self.enabled:
            return
        self.queue_depth.set(depth)

    def set_circuit_open(self, open_: bool) -> None:
        if not self.enabled:
            return
        self.circuit_state.set(1 if open_ else 0)

    def inference_stats(self) -> dict[str, int]:
        return {
            "model_calls_total": self._model_calls_total,
            "fallback_total": self._fallback_total,
            "parse_error_total": self._parse_error_total,
        }

    def render(self) -> tuple[bytes, str]:
        if not self.enabled or generate_latest is None or self.registry is None:
            return b"# metrics disabled\n", "text/plain; charset=utf-8"
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


_tracer = None


def configure_tracing(*, endpoint: str, service_name: str) -> None:
    global _tracer
    if not endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:  # pragma: no cover
        logging.getLogger(__name__).warning(
            "OTLP endpoint set but OpenTelemetry is not installed"
        )
        return

    provider = TracerProvider(
        resource=Resource.create({"service.name": service_name})
    )
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
    )
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("zeronode")


@contextmanager
def span(name: str, **attributes: str) -> Iterator[None]:
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            if value:
                current.set_attribute(key, value)
        yield


@contextmanager
def timed() -> Iterator[list[float]]:
    bucket = [0.0]
    started = time.perf_counter()
    try:
        yield bucket
    finally:
        bucket[0] = time.perf_counter() - started
