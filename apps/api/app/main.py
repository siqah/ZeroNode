from __future__ import annotations

import asyncio
import logging
import secrets
import urllib.request
from contextlib import asynccontextmanager
from typing import Any

from email_validator import EmailNotValidError, validate_email
from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from psycopg_pool import AsyncConnectionPool

from app.audit import store as audit_store
from app.audit.anchor import FileAnchorSink, NullAnchorSink
from app.audit.keys import KeySet
from app.audit.startup import verify_ledger_at_startup
from app.auth import store as user_store
from app.auth.models import Role
from app.auth.passwords import hash_password
from app.auth.ratelimit import SlidingWindow
from app.config import cypher_dir, settings
from app.config_validate import format_production_errors, validate_production_config
from app.execute import make_executor
from app.firewall.devices import BACKENDS
from app.firewall.mock import MockFirewall
from app.graph.builder import build_graph
from app.inference import make_llm
from app.jobs.dispatcher import InMemoryDispatcher, PostgresDispatcher
from app.jobs.runner import InvestigationRunner
from app.jobs.store import ensure_jobs_tables
from app.jobs.worker import Worker
from app.observability import (
    Metrics,
    configure_logging,
    configure_tracing,
)
from app.outbound import make_notifier, make_ticket_sink
from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.incidents import router as incidents_router
from app.routers.webhooks import router as webhooks_router
from app.schedule import ChangeSchedule
from app.secretref import SecretError, SecretResolver
from app.secretref import describe as describe_secret
from app.store.memory import InMemoryTopology
from app.store.topology_ingest import IngestResult, run_netbox_ingest

logger = logging.getLogger(__name__)
configure_logging(json_logs=settings.log_json, level=settings.log_level)
configure_tracing(
    endpoint=settings.otel_exporter_otlp_endpoint,
    service_name=settings.otel_service_name,
)


def _inference_status() -> tuple[bool, str]:
    backend = (settings.inference_backend or "ollama").strip().lower()
    if backend in {"vllm", "openai_compatible"}:
        base = settings.vllm_base_url.rstrip("/")
        model = settings.vllm_model or settings.ollama_model
        url = f"{base}/models"
        try:
            with urllib.request.urlopen(url, timeout=5):
                return True, f"{model} at {base} (vllm)"
        except Exception as exc:
            return False, f"unreachable at {base} ({exc})"
    url = settings.ollama_base_url.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=5):
            return True, f"{settings.ollama_model} at {settings.ollama_base_url} (ollama)"
    except Exception as exc:
        return False, f"unreachable at {settings.ollama_base_url} ({exc})"


def _check_inference() -> None:
    reachable, detail = _inference_status()
    if reachable:
        logger.info("Inference reachable: %s", detail)
    else:
        logger.error("Inference %s", detail)


def _make_llm():
    return make_llm(settings)


def _make_firewall():
    backend = (settings.firewall_backend or "mock").strip().lower()
    if backend == "mock":
        return MockFirewall()
    from app.firewall.devices import make_device_firewall

    if backend in BACKENDS and backend != "mock":
        return make_device_firewall(backend)
    raise RuntimeError(f"Unknown FIREWALL_BACKEND: {backend!r}")


def _resolver() -> SecretResolver:
    return SecretResolver(
        ttl_seconds=settings.secret_cache_seconds,
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
    )


def _secret(resolver: SecretResolver, reference: str, label: str) -> str:
    """Resolve a configured credential, failing startup rather than running with
    a silently empty one."""
    try:
        value = resolver.resolve(reference)
    except SecretError as exc:
        raise RuntimeError(f"{label}: {exc}") from exc
    if reference:
        logger.info("%s resolves from %s", label, describe_secret(reference))
    return value


def _configure_auth(app: FastAPI) -> None:
    resolver = _resolver()
    app.state.secrets = resolver
    app.state.auth_enabled = settings.auth_enabled
    app.state.jwt_ttl_minutes = settings.jwt_ttl_minutes
    app.state.service_token = _secret(resolver, settings.service_token, "SERVICE_TOKEN")
    app.state.mfa_required_for_approvers = settings.mfa_required_for_approvers
    app.state.login_limiter = SlidingWindow(
        settings.login_rate_limit, settings.login_rate_window_seconds
    )
    app.state.webhook_limiter = SlidingWindow(
        settings.webhook_rate_limit, settings.webhook_rate_window_seconds
    )
    if settings.auth_enabled and not settings.cookie_secure:
        logger.warning(
            "COOKIE_SECURE is false; session cookies will travel over plain HTTP. "
            "Set it once the dashboard is behind TLS."
        )

    if not settings.auth_enabled:
        logger.warning(
            "AUTH IS DISABLED. Every endpoint is open and approvals are unattributable. "
            "Never run this way outside local development."
        )

    secret = _secret(resolver, settings.jwt_secret, "JWT_SECRET")
    if not secret:
        secret = secrets.token_urlsafe(48)
        if settings.auth_enabled:
            logger.warning(
                "JWT_SECRET is unset; using a random secret. Every restart invalidates "
                "all sessions and multiple replicas will reject each other's tokens."
            )
    app.state.jwt_secret = secret

    keyset = KeySet.from_settings(
        _secret(resolver, settings.audit_signing_key, "AUDIT_SIGNING_KEY"),
        settings.audit_retired_keys,
    )
    if settings.audit_signing_key and not keyset.active.ephemeral:
        try:
            _ = keyset.active.public_key_b64
        except Exception as exc:
            raise RuntimeError(
                "AUDIT_SIGNING_KEY is invalid; generate one with: python -m app.audit.keys generate"
            ) from exc
    if keyset.active.ephemeral:
        logger.warning(
            "AUDIT_SIGNING_KEY is unset; the approval ledger is signing with an "
            "ephemeral key, so records written now cannot be verified after a restart. "
            "Generate one with: python -m app.audit.keys generate"
        )
    app.state.keyset = keyset
    app.state.signer = keyset.active

    if settings.audit_anchor_file:
        app.state.anchor_sink = FileAnchorSink(settings.audit_anchor_file)
    else:
        app.state.anchor_sink = NullAnchorSink()
        logger.warning(
            "AUDIT_ANCHOR_FILE is unset; deleting the whole approval ledger would "
            "leave no trace. Point it at a volume Postgres cannot write to."
        )


async def _bootstrap_admin(app: FastAPI, pool) -> None:
    email = settings.bootstrap_admin_email.strip()
    password = _secret(
        app.state.secrets, settings.bootstrap_admin_password, "BOOTSTRAP_ADMIN_PASSWORD"
    )
    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        if not email or not password:
            existing = await user_store.list_users(conn)
            if not existing and settings.auth_enabled:
                logger.error(
                    "No users exist and BOOTSTRAP_ADMIN_EMAIL/PASSWORD are unset: "
                    "nobody can log in or approve a change."
                )
            return
        created = await user_store.create_if_absent(
            conn, email, hash_password(password), Role.ADMIN
        )
    if created:
        logger.info("Bootstrapped admin user %s", email)

    # The login endpoint validates the address, and this does not go through it.
    # A reserved domain such as .local creates an account that can never be used,
    # which is only discovered at the first login attempt.
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError as exc:
        logger.error(
            "BOOTSTRAP_ADMIN_EMAIL %s is not an address the login endpoint accepts "
            "(%s); this account cannot be logged into.",
            email,
            exc,
        )


def make_topology(strict: bool, resolver: SecretResolver) -> tuple[Any, str]:
    """Returns (store, degradation). A degradation is empty when all is well.

    Falling back to the in-memory lab topology means the agent reasons about a
    network that is not the one in front of it, which is worse than not
    answering, so strict mode refuses to start instead.
    """
    try:
        from app.store.neo4j_store import Neo4jTopology

        store = Neo4jTopology(
            settings.neo4j_uri,
            settings.neo4j_user,
            _secret(resolver, settings.neo4j_password, "NEO4J_PASSWORD"),
            site=settings.topology_site,
        )
        store.ensure_seed(cypher_dir())
        logger.info("Neo4j topology ready at %s", settings.neo4j_uri)
        return store, ""
    except Exception as exc:
        if strict:
            raise RuntimeError(
                f"Neo4j is unavailable at {settings.neo4j_uri} ({exc}). The in-memory "
                "topology describes the lab, not your network; set "
                "STRICT_DEPENDENCIES=false only for local development."
            ) from exc
        logger.exception("Neo4j unavailable; using in-memory lab topology")
        return InMemoryTopology(), "topology: in-memory lab fixture, not the real network"


async def open_pool(
    strict: bool, resolver: SecretResolver, timeout: float = 10.0
) -> tuple[AsyncConnectionPool | None, str]:
    """Returns (pool, degradation).

    Without Postgres there is no checkpointer, no user table and no approval
    ledger: investigations vanish on restart and no decision can be recorded.
    """
    database_url = _secret(resolver, settings.database_url, "DATABASE_URL")
    pool = AsyncConnectionPool(
        conninfo=database_url,
        max_size=20,
        kwargs={"autocommit": True, "prepare_threshold": 0},
        open=False,
    )
    try:
        # wait=True, or an unreachable database looks like a healthy pool that
        # only fails on the first query, well after startup has declared itself
        # fine.
        await pool.open(wait=True, timeout=timeout)
        return pool, ""
    except Exception as exc:
        await pool.close()
        if strict:
            raise RuntimeError(
                f"Postgres is unavailable ({exc}). Without it nothing is durable: no "
                "checkpoints, no users, no approval ledger. Set STRICT_DEPENDENCIES=false "
                "only for local development."
            ) from exc
        logger.exception("Postgres unavailable; falling back to in-memory checkpointing")
        return None, "storage: in-memory, so incidents and approvals are lost on restart"


def _run_topology_ingest(resolver: SecretResolver) -> IngestResult | None:
    url = (settings.netbox_url or "").strip()
    token = (
        _secret(resolver, settings.netbox_token, "NETBOX_TOKEN")
        if settings.netbox_token
        else ""
    )
    if not url or not token:
        return None
    return run_netbox_ingest(
        url=url,
        token=token,
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=_secret(resolver, settings.neo4j_password, "NEO4J_PASSWORD"),
        site=settings.topology_site,
        replace=settings.topology_replace_on_ingest,
        verify_tls=settings.netbox_verify_tls,
    )


async def _topology_ingest_loop(app: FastAPI, resolver: SecretResolver) -> None:
    interval = max(int(settings.topology_ingest_interval_seconds or 0), 60)
    while True:
        try:
            result = await asyncio.to_thread(_run_topology_ingest, resolver)
            if result is not None:
                app.state.topology_freshness = result.as_dict()
        except Exception:
            logger.exception("scheduled topology ingest failed")
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    strict = settings.strict_dependencies
    degradations: list[str] = []
    embedded_worker: asyncio.Task | None = None
    topology_ingest_task: asyncio.Task | None = None

    production_errors = validate_production_config(settings)
    if production_errors:
        raise RuntimeError(format_production_errors(production_errors))

    _configure_auth(app)
    app.state.schedule = ChangeSchedule(
        settings.change_windows, settings.change_freezes, settings.change_window_tz
    )
    logger.info("Change schedule: %s", app.state.schedule.describe())
    if app.state.keyset.active.ephemeral and settings.auth_enabled:
        degradations.append("audit: signing key is ephemeral, records die with this process")

    topology, degraded = make_topology(strict, app.state.secrets)
    if degraded:
        degradations.append(degraded)

    firewall = _make_firewall()
    logger.info("Firewall backend: %s", firewall.describe())
    executor = make_executor(firewall)
    logger.info("Execution mode: %s", executor.describe())
    app.state.tickets = make_ticket_sink()
    app.state.notifier = make_notifier()
    logger.info("Ticketing: %s", app.state.tickets.describe())
    logger.info("Notifications: %s", app.state.notifier.describe())
    _check_inference()
    llm, circuit = _make_llm()
    app.state.circuit = circuit
    app.state.metrics = Metrics(enabled=settings.metrics_enabled)
    app.state.settings = settings

    pool, degraded = await open_pool(strict, app.state.secrets)
    if degraded:
        degradations.append(degraded)

    checkpointer = None
    if pool is not None:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        checkpointer = AsyncPostgresSaver(pool)
        await checkpointer.setup()
        async with pool.connection() as conn:
            await ensure_jobs_tables(conn)
        dispatcher = PostgresDispatcher(
            pool,
            capacity=settings.job_queue_capacity,
            max_attempts=settings.job_max_attempts,
        )
    else:
        dispatcher = InMemoryDispatcher(
            capacity=settings.job_queue_capacity,
            max_attempts=settings.job_max_attempts,
        )
        if strict:
            degradations.append("queue: in-memory, investigations die with this process")
        else:
            degradations.append("queue: in-memory dispatcher (local/dev only)")

    app.state.pool = pool
    app.state.dispatcher = dispatcher
    graph = build_graph(
        llm, topology, checkpointer, firewall, executor, app.state.metrics, settings
    )

    if pool is not None:
        await _bootstrap_admin(app, pool)
        async with pool.connection() as conn:
            await audit_store.ensure_approvals_table(conn)
            rotated = await audit_store.ensure_rotation_record(
                conn, app.state.keyset, app.state.anchor_sink
            )
            anchor_check, anchor_reason = await verify_ledger_at_startup(
                conn,
                keyset=app.state.keyset,
                anchor_sink=app.state.anchor_sink,
            )
        if rotated:
            logger.info(
                "Signing key rotated; wrote a rotation marker to the ledger (%s)",
                rotated.hash[:12],
            )
        if not anchor_check.ok:
            message = f"audit: {anchor_reason or 'ledger/anchor verification failed'}"
            if settings.production_baseline:
                raise RuntimeError(message)
            degradations.append(message)
    elif settings.auth_enabled:
        logger.error(
            "No database connection: nobody can log in and no approval can be recorded."
        )

    if not settings.auth_enabled:
        degradations.append("auth: disabled, every endpoint is open and approvals are anonymous")
    if isinstance(app.state.anchor_sink, NullAnchorSink):
        degradations.append("audit: ledger head is not anchored, deletion would be undetectable")

    for note in degradations:
        logger.warning("RUNNING DEGRADED - %s", note)

    app.state.degradations = degradations
    app.state.graph = graph
    app.state.topology = topology
    app.state.topology_freshness = (
        topology.freshness() if hasattr(topology, "freshness") else None
    )

    if settings.netbox_url and settings.netbox_token:
        try:
            initial = await asyncio.to_thread(_run_topology_ingest, app.state.secrets)
            if initial is not None:
                app.state.topology_freshness = initial.as_dict()
                if hasattr(topology, "freshness"):
                    app.state.topology_freshness = topology.freshness()
        except Exception as exc:
            msg = f"topology: NetBox ingest failed ({exc})"
            logger.exception(msg)
            if strict:
                degradations.append(msg)
        if settings.topology_ingest_interval_seconds > 0:
            topology_ingest_task = asyncio.create_task(
                _topology_ingest_loop(app, app.state.secrets),
                name="topology-ingest",
            )

    app.state.firewall = firewall
    app.state.executor = executor
    app.state.memory_incidents = {}
    app.state.graph_failures = {}

    # Wire idempotent execution lookups once the dispatcher exists.
    from app.execute.idempotent import IdempotentDeviceExecutor

    if isinstance(executor, IdempotentDeviceExecutor):
        # Keep a process-local mirror so the sync device path never awaits.
        cache: dict[str, dict] = {}

        async def _warm(key: str) -> dict | None:
            if key in cache:
                return cache[key]
            value = await dispatcher.get_execution(key)
            if value is not None:
                cache[key] = value
            return value

        def _lookup(key: str) -> dict | None:
            return cache.get(key)

        def _store(key: str, thread_id: str, result: dict) -> None:
            cache[key] = dict(result)
            # Persist in the background; the local mirror already makes retries
            # within this process idempotent.
            asyncio.create_task(dispatcher.put_execution(key, thread_id, result))

        executor.lookup = _lookup
        executor.store = _store
        app.state.warm_execution = _warm

    # In-memory mode always embeds a worker. Postgres production uses the
    # dedicated worker service unless WORKER_EMBEDDED is set for local runs.
    if isinstance(dispatcher, InMemoryDispatcher) or settings.worker_embedded:
        worker = Worker(
            dispatcher,
            InvestigationRunner(app.state),
            metrics=app.state.metrics,
        )
        embedded_worker = asyncio.create_task(worker.run_forever(), name="embedded-worker")
        app.state.embedded_worker = worker
        if settings.worker_embedded and not isinstance(dispatcher, InMemoryDispatcher):
            logger.warning(
                "WORKER_EMBEDDED is set: the API process is also polling jobs. "
                "Prefer the dedicated worker service in production."
            )

    yield
    if topology_ingest_task is not None:
        topology_ingest_task.cancel()
        try:
            await topology_ingest_task
        except asyncio.CancelledError:
            pass
    if embedded_worker is not None:
        worker = getattr(app.state, "embedded_worker", None)
        if worker is not None:
            worker.request_stop()
        embedded_worker.cancel()
        try:
            await embedded_worker
        except asyncio.CancelledError:
            pass
    if pool is not None:
        await pool.close()
    for resource in (topology, firewall):
        close = getattr(resource, "close", None)
        if callable(close):
            close()


app = FastAPI(title="ZeroNode", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[item.strip() for item in settings.cors_origins.split(",") if item.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(incidents_router)
if settings.webhooks_enabled:
    app.include_router(webhooks_router)


@app.get("/health")
async def health(response: Response):
    """Reports degradation instead of hiding it.

    A system that quietly swapped its durable stores for in-memory ones looks
    identical to a healthy one from the outside, which is how an audit trail
    goes missing without anybody noticing. Any degradation makes this endpoint
    fail, so an orchestrator or a monitor sees it.
    """
    degradations = list(getattr(app.state, "degradations", []))
    inference_ok, inference_detail = await asyncio.to_thread(_inference_status)
    if not inference_ok:
        degradations.append(f"Inference {inference_detail}")

    queue_info: dict[str, Any] = {"backend": "unset"}
    dispatcher = getattr(app.state, "dispatcher", None)
    if dispatcher is not None:
        queue_info = await dispatcher.health(
            stale_after_seconds=max(settings.job_lease_seconds * 2, 30)
        )
        metrics = getattr(app.state, "metrics", None)
        if metrics is not None:
            metrics.set_queue_depth(int(queue_info.get("depth") or 0))
        if (
            queue_info.get("backend") == "postgres"
            and int(queue_info.get("live_workers") or 0) == 0
            and not settings.worker_embedded
        ):
            # Production must run the dedicated worker service.
            degradations.append("worker: no live investigation worker heartbeat")
        if queue_info.get("saturated"):
            degradations.append(
                f"queue: saturated ({queue_info.get('depth')}/{queue_info.get('capacity')})"
            )

    circuit = getattr(app.state, "circuit", None)
    circuit_info = circuit.snapshot() if circuit is not None else {"state": "unset"}
    if circuit is not None:
        metrics = getattr(app.state, "metrics", None)
        if metrics is not None:
            metrics.set_circuit_open(circuit.state() == "open")
        if circuit.state() == "open":
            degradations.append("inference: circuit_open")

    metrics = getattr(app.state, "metrics", None)
    inference_stats = metrics.inference_stats() if metrics is not None else {}
    if (
        settings.model_fallback_degrades_health
        and int(inference_stats.get("fallback_total") or 0) > 0
    ):
        degradations.append(
            f"inference: {inference_stats['fallback_total']} fallback turn(s) recorded"
        )

    topology = getattr(app.state, "topology", None)
    topology_freshness = getattr(app.state, "topology_freshness", None)
    if topology_freshness is None and hasattr(topology, "freshness"):
        topology_freshness = topology.freshness()
    topology_age = topology.age_seconds() if hasattr(topology, "age_seconds") else None
    if (
        settings.netbox_url
        and settings.netbox_token
        and topology_freshness is None
    ):
        degradations.append("topology: NetBox configured but graph has no ingest metadata")
    if (
        topology_age is not None
        and settings.topology_stale_seconds > 0
        and topology_age > settings.topology_stale_seconds
    ):
        degradations.append(
            f"topology: stale ({int(topology_age)}s > {int(settings.topology_stale_seconds)}s)"
        )

    if degradations:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "ok": not degradations,
        "degradations": degradations,
        "components": {
            "topology": type(getattr(app.state, "topology", None)).__name__,
            "topology_freshness": topology_freshness,
            "topology_age_seconds": topology_age,
            "storage": "postgres" if getattr(app.state, "pool", None) else "in-memory",
            "queue": queue_info,
            "inference_circuit": circuit_info,
            "inference_quality": inference_stats,
            "firewall": app.state.firewall.describe()
            if getattr(app.state, "firewall", None)
            else "unset",
            "auth": "enabled" if settings.auth_enabled else "disabled",
            "inference": inference_detail,
            "execution": app.state.executor.describe()
            if getattr(app.state, "executor", None)
            else "unset",
            "tickets": app.state.tickets.describe()
            if getattr(app.state, "tickets", None)
            else "unset",
            "notifications": app.state.notifier.describe()
            if getattr(app.state, "notifier", None)
            else "unset",
            "change_window": app.state.schedule.describe()
            if getattr(app.state, "schedule", None)
            else "unset",
            "audit_key": getattr(app.state, "keyset", None).describe()["active_key_id"]
            if getattr(app.state, "keyset", None)
            else "unset",
            "audit_anchor": app.state.anchor_sink.describe()
            if getattr(app.state, "anchor_sink", None)
            else "unset",
        },
    }


@app.get("/metrics")
async def metrics():
    payload, content_type = getattr(app.state, "metrics", Metrics(enabled=False)).render()
    return Response(content=payload, media_type=content_type)
