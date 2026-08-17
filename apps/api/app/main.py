from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from langchain_ollama import ChatOllama
from psycopg_pool import AsyncConnectionPool

from app.config import cypher_dir, settings
from app.graph.builder import build_graph
from app.routers.incidents import router as incidents_router
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


def _make_topology():
    try:
        from app.store.neo4j_store import Neo4jTopology

        store = Neo4jTopology(
            settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password
        )
        store.ensure_seed(cypher_dir())
        logger.info("Neo4j topology ready at %s", settings.neo4j_uri)
        return store
    except Exception:
        logger.exception("Neo4j unavailable; using in-memory lab topology")
        return InMemoryTopology()


@asynccontextmanager
async def lifespan(app: FastAPI):
    topology = _make_topology()
    _check_ollama()
    llm = _make_llm()
    pool: AsyncConnectionPool | None = None
    try:
        pool = AsyncConnectionPool(
            conninfo=settings.database_url,
            max_size=20,
            kwargs={"autocommit": True, "prepare_threshold": 0},
            open=False,
        )
        await pool.open()
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        checkpointer = AsyncPostgresSaver(pool)
        await checkpointer.setup()
        graph = build_graph(llm, topology, checkpointer)
        app.state.pool = pool
    except Exception:
        logger.exception("Postgres checkpointer unavailable; using in-memory checkpointing")
        graph = build_graph(llm, topology)
        app.state.pool = None
        if pool is not None:
            await pool.close()
            pool = None

    app.state.graph = graph
    app.state.topology = topology
    app.state.memory_incidents = {}
    yield
    if pool is not None:
        await pool.close()
    close = getattr(topology, "close", None)
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
app.include_router(incidents_router)


@app.get("/health")
async def health():
    return {"ok": True}
