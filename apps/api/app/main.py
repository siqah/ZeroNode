from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from langchain_ollama import ChatOllama
from psycopg_pool import AsyncConnectionPool

from app.audit import store as audit_store
from app.audit.anchor import FileAnchorSink, NullAnchorSink
from app.audit.keys import KeySet
from app.auth import store as user_store
from app.auth.models import Role
from app.auth.passwords import hash_password
from app.auth.ratelimit import SlidingWindow
from app.config import cypher_dir, settings
from app.firewall.mock import MockFirewall
from app.graph.builder import build_graph
from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.incidents import router as incidents_router
from app.schedule import ChangeSchedule
from app.secretref import SecretError, SecretResolver
from app.secretref import describe as describe_secret
from app.store.memory import InMemoryTopology

logger = logging.getLogger(__name__)


def _check_ollama() -> None:
    import urllib.request

    url = settings.ollama_base_url.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=5):
            logger.info("Ollama reachable at %s", settings.ollama_base_url)
    except Exception as exc:
        logger.error("Ollama unreachable at %s (%s)", settings.ollama_base_url, exc)


def _make_llm():
    # No stop sequence: cutting on </tool_call> truncated the model mid-block and
    # left the harness to infer every call. The parser takes the first complete
    # block, so trailing commentary is harmless.
    return ChatOllama(
        model=settings.ollama_model,
        base_url=settings.ollama_base_url,
        num_predict=settings.ollama_num_predict,
        temperature=0,
    )


def _make_firewall():
    backend = (settings.firewall_backend or "mock").strip().lower()
    if backend == "mock":
        return MockFirewall()
    from app.firewall.devices import make_device_firewall

    if backend in ("cisco_asa", "cisco_ios"):
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


async def open_pool(strict: bool, timeout: float = 10.0) -> tuple[AsyncConnectionPool | None, str]:
    """Returns (pool, degradation).

    Without Postgres there is no checkpointer, no user table and no approval
    ledger: investigations vanish on restart and no decision can be recorded.
    """
    pool = AsyncConnectionPool(
        conninfo=settings.database_url,
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    strict = settings.strict_dependencies
    degradations: list[str] = []

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
    _check_ollama()
    llm = _make_llm()

    pool, degraded = await open_pool(strict)
    if degraded:
        degradations.append(degraded)

    checkpointer = None
    if pool is not None:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        checkpointer = AsyncPostgresSaver(pool)
        await checkpointer.setup()

    app.state.pool = pool
    graph = build_graph(llm, topology, checkpointer, firewall)

    if pool is not None:
        await _bootstrap_admin(app, pool)
        async with pool.connection() as conn:
            await audit_store.ensure_approvals_table(conn)
            rotated = await audit_store.ensure_rotation_record(
                conn, app.state.keyset, app.state.anchor_sink
            )
        if rotated:
            logger.info(
                "Signing key rotated; wrote a rotation marker to the ledger (%s)",
                rotated.hash[:12],
            )
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
    app.state.firewall = firewall
    app.state.memory_incidents = {}
    yield
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


@app.get("/health")
async def health(response: Response):
    """Reports degradation instead of hiding it.

    A system that quietly swapped its durable stores for in-memory ones looks
    identical to a healthy one from the outside, which is how an audit trail
    goes missing without anybody noticing. Any degradation makes this endpoint
    fail, so an orchestrator or a monitor sees it.
    """
    degradations = getattr(app.state, "degradations", [])
    if degradations:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "ok": not degradations,
        "degradations": degradations,
        "components": {
            "topology": type(getattr(app.state, "topology", None)).__name__,
            "storage": "postgres" if getattr(app.state, "pool", None) else "in-memory",
            "firewall": app.state.firewall.describe()
            if getattr(app.state, "firewall", None)
            else "unset",
            "auth": "enabled" if settings.auth_enabled else "disabled",
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
